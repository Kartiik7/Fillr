const mongoose = require('mongoose');

const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: { type: String, required: false },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: false }, // Optional for Google OAuth users
  // ── Authentication provider ───────────────────────────────
  // Tracks how the user registered — prevents password-less users from
  // authenticating via the email/password flow.
  // Backward compatible — existing users default to 'local'.
  authProvider: { type: String, enum: ['local', 'google'], default: 'local' },
  googleId:     { type: String, default: null }, // Google OAuth sub — index defined below
  displayName:  { type: String, default: '' }, // Name from Google profile
  profile: {
    personal: {
      name: { type: String, default: '' },
      email: { type: String, default: '' },
      phone: { type: String, default: '' },
      gender: { type: String, default: '' }, // Male/Female/Other
      dob: { type: String, default: '' }, // Date of Birth (YYYY-MM-DD)
      age: { type: String, default: '' }, // Age in years
      permanent_address: { type: String, default: '' }, // Permanent address
    },
    academics: {
      tenth_percentage: { type: String, default: '' },
      twelfth_percentage: { type: String, default: '' },
      diploma_percentage: { type: String, default: '' }, // Diploma percentage
      cgpa: { type: String, default: '' },
      graduation_percentage: { type: String, default: '' },
      pg_percentage: { type: String, default: '' },
      active_backlog: { type: String, default: 'No' }, // Yes/No
      backlog_count: { type: String, default: '0' },
      gap_months: { type: String, default: '0' }, // Gap in education (months)
    },
    ids: {
      uid: { type: String, default: '' },
      roll_number: { type: String, default: '' },
      university_roll_number: { type: String, default: '' },
    },
    links: {
      github: { type: String, default: '' },
      linkedin: { type: String, default: '' },
      portfolio: { type: String, default: '' },
    },
    // New fields for Placement Support
    education: {
      college_name: { type: String, default: '' },
      batch: { type: String, default: '' }, // e.g. 2024
      program: { type: String, default: '' }, // e.g. B.Tech
      stream: { type: String, default: '' }, // e.g. CSE
    },
    placement: {
      position_applying: { type: String, default: '' },
    },
  },
  // ── Legal consent (required for GDPR / SaaS compliance) ──
  // termsAccepted is enforced at registration — no bypass allowed.
  // Versioning fields allow re-prompting users if policies are updated.
  // Backward compatibility: defaults allow existing users to keep working.
  termsAccepted:    { type: Boolean, default: false },
  termsAcceptedAt:  { type: Date,    default: null  },
  termsVersion:     { type: String,  default: ''    }, // e.g. "1.0"
  privacyVersion:   { type: String,  default: ''    }, // e.g. "1.0"
  // ── Password reset (secure, single-use) ───────────────────
  // Raw token is NEVER stored — only a SHA-256 hash.
  // Expiry is 30 minutes from generation.
  // Both fields are cleared immediately after a successful reset.
  resetPasswordHash:   { type: String,  default: null, select: false },
  resetPasswordExpiry: { type: Date,    default: null, select: false },
  // ── Email verification ────────────────────────────────────
  // isVerified gates login for email/password users.
  // Google OAuth users are auto-verified (Google verifies their email).
  // Token is SHA-256 hashed (same pattern as password reset).
  isVerified:              { type: Boolean, default: false },
  verificationTokenHash:   { type: String,  default: null, select: false },
  verificationTokenExpiry: { type: Date,    default: null, select: false },
}, { timestamps: true });

// ── Indexes ───────────────────────────────────────────────────
// googleId index is sparse — only Google OAuth users have this field.
// Prevents duplicate googleId while allowing null for local users.
userSchema.index({ googleId: 1 }, { unique: true, sparse: true });

// Encrypt password using bcrypt — only for local auth users
userSchema.pre('save', async function () {
  if (!this.isModified('password') || !this.password) {
    return;
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Match user entered password to hashed password in database
userSchema.methods.matchPassword = async function (enteredPassword) {
  if (!this.password) return false; // Google OAuth users have no password
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
