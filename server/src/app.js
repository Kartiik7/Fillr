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
  ...(process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',').map(s => s.trim()) : []),
].filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile, Postman, server-to-server)
    if (!origin) return callback(null, true);
    // Allow whitelisted origins and chrome-extension:// scheme
    if (ALLOWED_ORIGINS.includes(origin) || /^chrome-extension:\/\//.test(origin)) {
      return callback(null, true);
    }
    callback(new Error(`CORS: origin '${origin}' not allowed`));
  },
  credentials: true,
  optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.options('/*', cors(corsOptions)); // Handle pre-flight for all routes

// ── Body parsing — with size limit ────────────────────────────
// Prevents payload-flooding DoS attacks
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

// ── NoSQL injection sanitization ──────────────────────────────
// Strips $ and . from keys — prevents $where, $gt, $regex injection
// Protects against: User.find(req.body) style injection attacks
app.use(mongoSanitize());

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

// ── Routes ────────────────────────────────────────────────────
app.use('/api/auth',    authRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/user',    userRoutes);
app.use('/api/keys',    keyRoutes);

// Health check — no sensitive data exposed
app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok' });
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
