/**
 * resetController.js — Secure password reset (minimal beta flow)
 *
 * Flow:
 *  1. POST /api/auth/forgot-password  — user submits email
 *     → Generate 32-byte random token
 *     → Store SHA-256 hash in DB (raw token NEVER stored)
 *     → Set 30-minute expiry
 *     → Send email with reset link containing raw token
 *     → Always respond "If an account exists…" (prevents email enumeration)
 *
 *  2. POST /api/auth/reset-password   — user submits token + new password
 *     → Hash the incoming token with SHA-256
 *     → Find user by hashed token + valid expiry
 *     → Set new password (bcrypt via User model pre-save hook)
 *     → Invalidate token (clear hash + expiry)
 *     → Respond success
 *
 * Security:
 *  - Token is 32 random bytes (256-bit entropy) — unguessable
 *  - Token stored as SHA-256 hash — even DB breach doesn't reveal token
 *  - 30-minute expiry — limits window of opportunity
 *  - Single-use — cleared after successful reset
 *  - Rate limited at route level (3 req / 15 min for forgot, 5 for reset)
 *  - No email enumeration — identical response regardless of email existence
 *  - Google OAuth users with no password CAN set one via this flow
 */

const crypto     = require('crypto');
const Joi        = require('joi');
const nodemailer = require('nodemailer');
const User       = require('../models/User');

// ── Email transporter ─────────────────────────────────────────
// Uses SMTP credentials from environment.
// For beta: Gmail App Password or any SMTP provider.
// SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS must be set in .env
const createTransporter = () => {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT, 10) || 587,
    secure: false, // true for 465, false for 587 (STARTTLS)
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
};

// ── Input schemas ─────────────────────────────────────────────
const forgotSchema = Joi.object({
  email: Joi.string().email({ tlds: { allow: false } }).max(254).lowercase().required(),
});

const resetSchema = Joi.object({
  token: Joi.string().hex().length(64).required(), // 32 bytes → 64 hex chars
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, and one number.',
      'string.min':          'Password must be at least 8 characters.',
      'string.max':          'Password is too long.',
    }),
});

// ── Token hashing (SHA-256) ───────────────────────────────────
// We use SHA-256 instead of bcrypt because:
//  - The raw token has 256-bit entropy → no brute-force risk
//  - SHA-256 is deterministic → allows DB lookup by hash
//  - bcrypt is designed for low-entropy passwords; overkill here
const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

// ── POST /api/auth/forgot-password ────────────────────────────
exports.forgotPassword = async (req, res, next) => {
  try {
    const { error, value } = forgotSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { email } = value;

    // ALWAYS return the same response — prevents email enumeration
    const GENERIC_MSG = 'If an account with that email exists, a password reset link has been sent.';

    const user = await User.findOne({ email }).select('+resetPasswordHash +resetPasswordExpiry');

    if (!user) {
      // No user found — return success anyway (anti-enumeration)
      return res.json({ success: true, message: GENERIC_MSG });
    }

    // Google-only users (no password set) CAN use this to set a password
    // This is intentional — allows them to add local auth as a backup

    // Generate random token (32 bytes = 256-bit entropy)
    const rawToken = crypto.randomBytes(32).toString('hex'); // 64 hex chars
    const hashed   = hashToken(rawToken);
    const expiry   = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes

    // Store hashed token + expiry on user
    user.resetPasswordHash   = hashed;
    user.resetPasswordExpiry = expiry;
    await user.save({ validateBeforeSave: false }); // Skip full validation — only updating reset fields

    // Build reset URL
    const frontendUrl = process.env.FRONTEND_URL || 'https://fillr-placement-autofill.netlify.app';
    const resetUrl    = `${frontendUrl}/reset-password.html?token=${rawToken}`;

    // Send email
    try {
      const transporter = createTransporter();
      await transporter.sendMail({
        from:    `"Fillr" <${process.env.SMTP_USER}>`,
        to:      email,
        subject: 'Reset your Fillr password',
        html: `
          <div style="font-family: 'Inter', Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px 24px;">
            <h2 style="color: #0f172a; font-size: 20px; margin-bottom: 8px;">Reset your password</h2>
            <p style="color: #475569; font-size: 14px; line-height: 1.6;">
              You requested a password reset for your Fillr account. Click the button below to set a new password.
              This link expires in <strong>30 minutes</strong>.
            </p>
            <a href="${resetUrl}"
               style="display: inline-block; margin: 24px 0; padding: 12px 28px;
                      background: #2563eb; color: #fff; font-size: 14px; font-weight: 600;
                      text-decoration: none; border-radius: 8px;">
              Reset Password
            </a>
            <p style="color: #94a3b8; font-size: 12px; line-height: 1.6;">
              If you didn't request this, you can safely ignore this email.<br>
              Your password will remain unchanged.
            </p>
            <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;">
            <p style="color: #cbd5e1; font-size: 11px;">Fillr — Placement Form Autofill</p>
          </div>
        `,
      });
    } catch (emailErr) {
      // Email failed — clear the token so it can't be used
      user.resetPasswordHash   = null;
      user.resetPasswordExpiry = null;
      await user.save({ validateBeforeSave: false });
      console.error('[Reset] Email send failed:', emailErr.message);
      // Still return generic message — don't reveal that sending failed for this specific email
      return res.json({ success: true, message: GENERIC_MSG });
    }

    return res.json({ success: true, message: GENERIC_MSG });
  } catch (err) {
    next(err);
  }
};

// ── POST /api/auth/reset-password ─────────────────────────────
exports.resetPassword = async (req, res, next) => {
  try {
    const { error, value } = resetSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { token, password } = value;

    // Hash the incoming token → compare with stored hash
    const hashed = hashToken(token);

    // Find user with matching hash AND non-expired token
    const user = await User.findOne({
      resetPasswordHash:   hashed,
      resetPasswordExpiry: { $gt: new Date() },
    }).select('+resetPasswordHash +resetPasswordExpiry');

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Reset link is invalid or has expired. Please request a new one.',
      });
    }

    // Set new password (bcrypt hashing happens in User model pre-save hook)
    user.password    = password;
    user.authProvider = 'local'; // If they were Google-only, they now also have local auth

    // Invalidate token — single-use enforcement
    user.resetPasswordHash   = null;
    user.resetPasswordExpiry = null;

    await user.save();

    return res.json({
      success: true,
      message: 'Password has been reset successfully. You can now log in with your new password.',
    });
  } catch (err) {
    next(err);
  }
};
