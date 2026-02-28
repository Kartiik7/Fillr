/**
 * app.js — Production-hardened Express application
 *
 * Threat model summary:
 *  - Helmet:              Clickjacking, MIME sniff, XSS reflections, referrer leaks
 *  - CORS whitelist:      CORS bypass via unexpected origin
 *  - Rate limiting:       Brute force, credential stuffing, rate abuse, DDoS
 *  - Body size limit:     Payload-based DoS / memory exhaustion
 *  - mongoSanitize:       NoSQL injection via $-operator keys in request body
 *  - Centralized errors:  Stack-trace / internal detail leakage in production
 */

const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const compression  = require('compression');
const rateLimit    = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const authRoutes    = require('./routes/authRoutes');
const profileRoutes = require('./routes/profileRoutes');
const userRoutes    = require('./routes/userRoutes');
const keyRoutes     = require('./routes/keyRoutes');

const isProd = process.env.NODE_ENV === 'production';
const app    = express();

// ── Trust proxy (required for rate limiting behind Render/Heroku/etc) ─
// Tells Express to trust X-Forwarded-* headers from the first proxy
app.set('trust proxy', 1);

// ── Security headers (OWASP baseline) ────────────────────────
// Sets: X-Content-Type-Options, X-Frame-Options, HSTS, CSP, etc.
app.use(helmet());
app.disable('x-powered-by'); // belt-and-suspenders; helmet already removes it

// ── Gzip compression ──────────────────────────────────────────
app.use(compression());

// ── Strict CORS ───────────────────────────────────────────────
// Protects against: CORS bypass via spoofed origins
// Reads allowed origins from CORS_ORIGINS env var (comma-separated).
// FRONTEND_URL is always included if set. chrome-extension:// is auto-allowed.
// Wildcard is NEVER allowed in production.
const ALLOWED_ORIGINS = [
  process.env.FRONTEND_URL,
  ...(process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',').map(s => s.trim().replace(/\/+$/, '')) : []),
].filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile, Postman, server-to-server)
    if (!origin) return callback(null, true);
    // Allow whitelisted origins and the specific Chrome extension
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    // Chrome extension — pin to specific ID in production, allow any in dev
    if (/^chrome-extension:\/\//.test(origin)) {
      const extId = process.env.EXTENSION_ID;
      if (!extId || origin === `chrome-extension://${extId}`) {
        return callback(null, true);
      }
    }
    callback(new Error(`CORS: origin '${origin}' not allowed`));
  },
  credentials: true,
  optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));

// ── Body parsing — with size limit ────────────────────────────
// Prevents payload-flooding DoS attacks
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

// ── NoSQL injection sanitization ──────────────────────────────
// Strips $ and . from keys — prevents $where, $gt, $regex injection
// Protects against: User.find(req.body) style injection attacks
// express-mongo-sanitize middleware is NOT used because Express 5 makes
// req.query read-only, causing "Cannot set property query" errors.
// Instead we use the sanitize() function directly on body & params.
app.use((req, _res, next) => {
  if (req.body)   mongoSanitize.sanitize(req.body);
  if (req.params) mongoSanitize.sanitize(req.params);
  next();
});

// ── Global rate limiter ───────────────────────────────────────
// Protects against: rate abuse, DDoS, brute force on non-auth routes
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests. Please try again later.' },
});
app.use(globalLimiter);

// ── Serve frontend static assets ───────────────────────────
const path = require('path');
const fs   = require('fs');
const CLIENT_DIR = path.join(__dirname, '../../client');
app.use(express.static(CLIENT_DIR));

// expose clean dashboard URL without extension
app.get('/dashboard', (_req, res) => {
  res.sendFile(path.join(CLIENT_DIR, 'dashboard.html'));
});

// generic handler for other top-level pages (login, register, etc.)
app.get('/:page', (req, res, next) => {
  const page = req.params.page;
  // avoid interfering with API routes
  if (page.startsWith('api')) return next();
  const file = path.join(CLIENT_DIR, `${page}.html`);
  fs.access(file, fs.constants.F_OK, (err) => {
    if (err) return next(); // not found, continue to next handler
    res.sendFile(file);
  });
});

// ── Routes ────────────────────────────────────────────────────
app.use('/api/auth',    authRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/user',    userRoutes);
app.use('/api/keys',    keyRoutes);

// Health check — includes DB readiness
const mongoose = require('mongoose');
app.get('/health', (_req, res) => {
  const dbReady = mongoose.connection.readyState === 1; // 1 = connected
  const status  = dbReady ? 'ok' : 'degraded';
  res.status(dbReady ? 200 : 503).json({ status, db: dbReady ? 'connected' : 'disconnected' });
});

// ── 404 handler ───────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route not found.' });
});

// ── Centralized error handler ─────────────────────────────────
// Does NOT leak stack traces or internal messages in production.
// Protects against: internal detail / path disclosure
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  const status = err.status || err.statusCode || 500;
  if (isProd) {
    // Log server-side only — never expose to client
    console.error(`[Error] ${err.message}`);
    return res.status(status).json({
      success: false,
      message: err.expose ? err.message : 'An unexpected error occurred.',
    });
  }
  // Development — richer detail ok
  console.error(err);
  res.status(status).json({ success: false, message: err.message, stack: err.stack });
});

module.exports = app;
