/**
 * server.js — Application entry point
 *
 * Startup guards:
 *  - Fails fast if JWT_SECRET is missing or too short (< 32 chars)
 *  - Fails fast if MONGO_URI is not set
 *  - Catches unhandled rejections / exceptions without crashing silently
 */

require('dotenv').config();

const app       = require('./src/app');
const connectDB = require('./src/config/db');

const isProd = process.env.NODE_ENV === 'production';
const PORT   = process.env.PORT || 5000;

// ── Startup environment guards ────────────────────────────────
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error('[FATAL] JWT_SECRET is missing or too short (need 32+ chars). Set it in your environment variables.');
  process.exit(1);
}

if (!process.env.MONGO_URI) {
  console.error('[FATAL] MONGO_URI is not set in environment variables.');
  process.exit(1);
}

if (!process.env.GOOGLE_CLIENT_ID) {
  console.warn('[WARN] GOOGLE_CLIENT_ID is not set. Google OAuth login will not work.');
}

// ── Graceful unhandled error handling ───────────────────────
// Prevents silent failures and uncontrolled crashes
process.on('unhandledRejection', (reason) => {
  console.error('[Server] Unhandled Rejection:', isProd ? String(reason?.message || reason) : reason);
});

process.on('uncaughtException', (err) => {
  console.error('[Server] Uncaught Exception:', isProd ? err.message : err);
  process.exit(1);
});

// ── Start ─────────────────────────────────────────────────────
connectDB().then(() => {
  app.listen(PORT, () => {
    if (!isProd) console.log(`[Server] Running on http://localhost:${PORT}`);
    else console.log('[Server] Started.');
  });
});
