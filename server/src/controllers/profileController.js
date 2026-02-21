/**
 * profileController.js — Profile CRUD + GDPR endpoints
 *
 * Protects against:
 *  - Mass assignment / over-posting: Explicit field whitelisting via pick* helpers.
 *    req.body is NEVER passed directly into a DB query or Model.create().
 *  - NoSQL injection:  mongoSanitize strips $-keys upstream; pick* ignores extras.
 *  - Password hash leakage: All queries use .select('-password -__v').
 *  - Internal error leakage: All errors forwarded to centralized handler via next().
 *  - Mongo raw error exposure: No mongoose error objects returned to client.
 */

const User = require('../models/User');

// ── Field whitelisting helpers ────────────────────────────────
// Only explicitly listed keys are ever written to the database.
// Any injected keys ($where, __proto__, constructor, etc.) are silently dropped.

const pickPersonal = (src = {}) => ({
  name:              src.name,
  phone:             src.phone,
  gender:            src.gender,
  dob:               src.dob,
  age:               src.age,
  permanent_address: src.permanent_address,
});

const pickAcademics = (src = {}) => ({
  tenth_percentage:      src.tenth_percentage,
  twelfth_percentage:    src.twelfth_percentage,
  diploma_percentage:    src.diploma_percentage,
  graduation_percentage: src.graduation_percentage,
  pg_percentage:         src.pg_percentage,
  cgpa:                  src.cgpa,
  active_backlog:        src.active_backlog,
  backlog_count:         src.backlog_count,
  gap_months:            src.gap_months,
});

const pickIds = (src = {}) => ({
  uid:                    src.uid,
  roll_number:            src.roll_number,
  university_roll_number: src.university_roll_number,
});

const pickLinks = (src = {}) => ({
  github:    src.github,
  linkedin:  src.linkedin,
  portfolio: src.portfolio,
});

const pickEducation = (src = {}) => ({
  college_name: src.college_name,
  batch:        src.batch,
  program:      src.program,
  stream:       src.stream,
});

const pickPlacement = (src = {}) => ({
  position_applying: src.position_applying,
});

// ── Helpers ───────────────────────────────────────────────────
// Apply only defined (non-undefined) picked values to a sub-document
const applyPicked = (subDoc, picked) => {
  Object.entries(picked).forEach(([k, v]) => {
    if (v !== undefined) subDoc[k] = v;
  });
};

// ── GET /api/profile ──────────────────────────────────────────
exports.getProfile = async (req, res, next) => {
  try {
    // Never return password hash or internal Mongo fields
    const user = await User.findById(req.user._id).select('-password -__v').lean();
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    return res.json({ success: true, profile: user.profile, email: user.email });
  } catch (err) {
    next(err); // Centralized handler — no raw error exposed to client
  }
};

// ── PUT /api/profile ──────────────────────────────────────────
exports.updateProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select('-password -__v');
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    // Destructure ONLY the known top-level keys
    const { personal, academics, ids, links, education, placement } = req.body.profile || {};

    if (personal)   applyPicked(user.profile.personal,   pickPersonal(personal));
    if (academics)  applyPicked(user.profile.academics,  pickAcademics(academics));
    if (ids)        applyPicked(user.profile.ids,         pickIds(ids));
    if (links)      applyPicked(user.profile.links,       pickLinks(links));
    if (education)  applyPicked(user.profile.education,   pickEducation(education));
    if (placement)  applyPicked(user.profile.placement,   pickPlacement(placement));

    user.markModified('profile');
    const saved = await user.save();

    return res.json({
      success: true,
      message: 'Profile updated successfully.',
      profile: saved.profile,
    });
  } catch (err) {
    next(err);
  }
};

// ── GET /api/profile/my-data — GDPR: Data access ─────────────
// Returns all stored PII for the authenticated user.
// Required by GDPR Art. 15 (right of access).
exports.getMyData = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select('-password -__v').lean();
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    return res.json({
      success: true,
      data: {
        email:     user.email,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        profile:   user.profile,
      },
    });
  } catch (err) {
    next(err);
  }
};

// ── DELETE /api/profile/account ───────────────────────────────
// REMOVED — account deletion is handled exclusively by
// DELETE /api/user/delete (userController.deleteAccount)
// which requires password verification and cleans up ExtensionKeys.
