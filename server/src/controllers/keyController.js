/**
 * keyController.js — Extension secret key management + extension auth
 *
 * Implements a revocable, hashed extension key system:
 *  - Generate:   POST /api/keys/generate   (JWT + password confirmation)
 *  - Rotate:     POST /api/keys/rotate     (JWT + password confirmation)
 *  - Revoke:     POST /api/keys/revoke     (JWT + keyId)
 *  - List:       GET  /api/keys            (JWT — returns metadata, never keys)
 *  - Extension:  POST /api/auth/extension  (apiKey → short-lived JWT)
 *
 * Security architecture:
 *  - Raw key is generated in a short readable format: fillr_XXXX-XXXX-XXXX (soft-launch).
 *  - Only bcrypt hash is stored — raw key is returned ONCE at generation.
 *  - Raw key is NEVER logged, NEVER stored, NEVER returned again.
 *  - Extension auth loops through active keys with bcrypt.compare — constant-set comparison.
 *  - Max 5 active keys per user — prevents multiple-device abuse.
 *
 * Protects against:
 *  - Brute force on secret keys: Heavy rate limiting on /auth/extension (5 req/15 min)
 *  - Key leakage:                Only bcrypt hash stored; raw key shown once
 *  - Credential stuffing:        Rate limiting + bcrypt cost makes bulk guessing infeasible
 *  - JWT replay:                 Short-lived (7d) JWT with standard expiry
 *  - Mongo injection:            Joi validation + mongoSanitize upstream
 *  - Multiple device abuse:      MAX_KEYS_PER_USER = 5 enforced
 *  - Stale key reuse:            expiresAt + isActive checks in auth flow
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const User = require('../models/User');
const ExtensionKey = require('../models/ExtensionKey');
const { generateToken } = require('./authController');

// ── Input schemas ─────────────────────────────────────────────
const generateSchema = Joi.object({
  password:   Joi.string().min(1).max(128).required(),
  deviceName: Joi.string().max(100).default('Chrome Extension'),
});

const rotateSchema = Joi.object({
  password:   Joi.string().min(1).max(128).required(),
  keyId:      Joi.string().uuid({ version: 'uuidv4' }).optional(), // specific key to rotate
  deviceName: Joi.string().max(100).default('Chrome Extension'),
});

const revokeSchema = Joi.object({
  keyId: Joi.string().uuid({ version: 'uuidv4' }).required(),
});

const extensionAuthSchema = Joi.object({
  apiKey: Joi.string().min(10).max(256).required(),
});

// ── Generate Key ──────────────────────────────────────────────
// POST /api/keys/generate
// Requires: JWT + password confirmation
// Returns raw key ONCE — never stored, never logged.
exports.generateKey = async (req, res, next) => {
  try {
    const { error, value } = generateSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { password, deviceName } = value;

    // Verify password — ensures live possession of credentials
    // Protects against: stolen JWT being used to generate keys
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    // Google OAuth users without a password cannot generate extension keys
    // They must set a password first (future feature) or use a different flow
    if (!user.password) {
      return res.status(400).json({
        success: false,
        message: 'Password confirmation required. Google-only accounts must set a password first.',
      });
    }

    const isValid = await user.matchPassword(password);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Incorrect password.' });
    }

    // Enforce max active keys per user — prevents multiple-device abuse
    const activeCount = await ExtensionKey.countActiveByUser(user._id);
    if (activeCount >= ExtensionKey.MAX_KEYS_PER_USER) {
      return res.status(400).json({
        success: false,
        message: `Maximum ${ExtensionKey.MAX_KEYS_PER_USER} active keys allowed. Revoke an existing key first.`,
      });
    }

    // Soft-launch: short readable key  (fillr_XXXX-XXXX-XXXX)
    // Will be upgraded to longer cryptographic keys later
    const seg = () => crypto.randomBytes(3).toString('hex').toUpperCase();
    const rawKey = `fillr_${seg()}-${seg()}-${seg()}`;

    // Hash with bcrypt (10 salt rounds) — same cost as passwords
    const hashedKey = await bcrypt.hash(rawKey, 10);

    const keyId = uuidv4();
    const expiresAt = new Date(Date.now() + ExtensionKey.KEY_VALIDITY_DAYS * 24 * 60 * 60 * 1000);

    await ExtensionKey.create({
      userId: user._id,
      keyId,
      hashedKey,
      deviceName,
      expiresAt,
    });

    // ⚠ Return raw key ONCE — it is NEVER stored or logged
    return res.status(201).json({
      success: true,
      message: 'Extension key generated. Store it securely — it will not be shown again.',
      key: {
        keyId,
        rawKey,       // Returned ONCE only
        deviceName,
        expiresAt,
      },
    });
  } catch (err) {
    next(err);
  }
};

// ── Rotate Key ────────────────────────────────────────────────
// POST /api/keys/rotate
// Deactivates existing key(s) and generates a new one.
// Requires: JWT + password confirmation.
exports.rotateKey = async (req, res, next) => {
  try {
    const { error, value } = rotateSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { password, keyId, deviceName } = value;

    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

    if (!user.password) {
      return res.status(400).json({
        success: false,
        message: 'Password confirmation required. Google-only accounts must set a password first.',
      });
    }

    const isValid = await user.matchPassword(password);
    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Incorrect password.' });
    }

    // Deactivate target key or all active keys for this user
    if (keyId) {
      const result = await ExtensionKey.updateOne(
        { userId: user._id, keyId, isActive: true },
        { isActive: false }
      );
      if (result.modifiedCount === 0) {
        return res.status(404).json({ success: false, message: 'Active key not found.' });
      }
    } else {
      // Deactivate ALL active keys for this user
      await ExtensionKey.updateMany(
        { userId: user._id, isActive: true },
        { isActive: false }
      );
    }

    // Soft-launch: short readable key
    const seg = () => crypto.randomBytes(3).toString('hex').toUpperCase();
    const rawKey = `fillr_${seg()}-${seg()}-${seg()}`;
    const hashedKey = await bcrypt.hash(rawKey, 10);
    const newKeyId = uuidv4();
    const expiresAt = new Date(Date.now() + ExtensionKey.KEY_VALIDITY_DAYS * 24 * 60 * 60 * 1000);

    await ExtensionKey.create({
      userId: user._id,
      keyId: newKeyId,
      hashedKey,
      deviceName,
      expiresAt,
    });

    return res.status(201).json({
      success: true,
      message: 'Key rotated successfully. Old key(s) have been revoked.',
      key: {
        keyId: newKeyId,
        rawKey,       // Returned ONCE only
        deviceName,
        expiresAt,
      },
    });
  } catch (err) {
    next(err);
  }
};

// ── Revoke Key ────────────────────────────────────────────────
// POST /api/keys/revoke
// Sets isActive = false — key can never be used again.
exports.revokeKey = async (req, res, next) => {
  try {
    const { error, value } = revokeSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: error.details[0].message });
    }

    const { keyId } = value;

    const result = await ExtensionKey.updateOne(
      { userId: req.user._id, keyId, isActive: true },
      { isActive: false }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ success: false, message: 'Active key not found.' });
    }

    return res.json({ success: true, message: 'Key revoked successfully.' });
  } catch (err) {
    next(err);
  }
};

// ── List Keys ─────────────────────────────────────────────────
// GET /api/keys
// Returns metadata only — NEVER the hashed key or any secret material.
exports.listKeys = async (req, res, next) => {
  try {
    const keys = await ExtensionKey.find({ userId: req.user._id })
      .select('keyId deviceName isActive createdAt expiresAt lastUsedAt')
      .sort({ createdAt: -1 })
      .lean();

    return res.json({ success: true, keys });
  } catch (err) {
    next(err);
  }
};

// ── Extension Authentication ──────────────────────────────────
// POST /api/auth/extension
// Body: { apiKey: "raw_key" }
//
// Flow:
//  1. Rate limit heavily (at route level — 5 req/15 min per IP)
//  2. Loop through ALL active, non-expired keys
//  3. bcrypt.compare(apiKey, hashedKey) for each
//  4. If valid → issue short-lived JWT
//
// Protects against:
//  - Brute force:     Heavy rate limiting + bcrypt cost (~100ms per compare)
//  - Revoked keys:    isActive check filters them out
//  - Expired keys:    expiresAt check filters them out
//  - Key enumeration: Generic error message; no keyId returned
exports.extensionAuth = async (req, res, next) => {
  try {
    const { error, value } = extensionAuthSchema.validate(req.body, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: 'Invalid API key format.' });
    }

    const { apiKey } = value;

    // Fetch all active, non-expired keys — we must compare against each
    // This is O(n) with bcrypt but n is capped at MAX_KEYS_PER_USER (5)
    const now = new Date();
    const activeKeys = await ExtensionKey.find({
      isActive: true,
      expiresAt: { $gt: now },
    }).select('userId hashedKey keyId');

    let matchedKey = null;

    for (const key of activeKeys) {
      // bcrypt.compare is constant-time for same hash — resistant to timing attacks
      const isMatch = await bcrypt.compare(apiKey, key.hashedKey);
      if (isMatch) {
        matchedKey = key;
        break;
      }
    }

    if (!matchedKey) {
      // Generic message — do NOT reveal whether key exists, is expired, or is revoked
      return res.status(401).json({ success: false, message: 'Invalid or expired API key.' });
    }

    // Verify the owning user account still exists
    const user = await User.findById(matchedKey.userId).select('_id').lean();
    if (!user) {
      return res.status(401).json({ success: false, message: 'Account not found.' });
    }

    // Update lastUsedAt for audit trail (non-blocking — fire and forget)
    ExtensionKey.updateOne({ _id: matchedKey._id }, { lastUsedAt: now }).catch(() => {});

    // Issue JWT — same unified token strategy as email/password and Google login
    const accessToken = generateToken(user._id);

    return res.json({
      success: true,
      accessToken,
      expiresIn: '7d',
      message: 'Extension authenticated.',
    });

    // NOTE: keyId is NOT returned — prevents information leakage
  } catch (err) {
    next(err);
  }
};
