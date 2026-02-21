/**
 * profileRoutes.js — Profile routes (all require valid JWT)
 */

const express        = require('express');
const profileController = require('../controllers/profileController');
const authMiddleware    = require('../middleware/authMiddleware');

const router = express.Router();

// Core profile endpoints
router.get('/',  authMiddleware, profileController.getProfile);
router.put('/',  authMiddleware, profileController.updateProfile);

// GDPR compliance endpoints
// GET  /api/profile/my-data  — Art. 15: Right of access
// DELETE /api/profile/account — REMOVED: use DELETE /api/user/delete instead
router.get('/my-data',  authMiddleware, profileController.getMyData);

module.exports = router;
