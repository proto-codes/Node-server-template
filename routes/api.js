const express = require('express');

const authController = require('../controllers/authController');
const userController = require('../controllers/userController');

const router = express.Router();

// Logout Route
router.post('/logout', authController.logout);

// Token verification
router.get('/verify-account', authController.verifyAccount);
router.post('/request-verification-token', authController.requestVerificationToken);

// Token validation route
router.post('/validate-token', (req, res) => {
  const newAccessToken = req.newAccessToken;
  if (newAccessToken) {
    return res.status(200).json({ id: req.user.id, newAccessToken });
  }
  res.status(200).json({ user: req.user });
});

// User settings routes
router.put('/change-password', userController.changePassword);
router.put('/notification-preferences', userController.updateNotificationPreferences);
router.delete('/delete-account', userController.deleteAccount);

// User routes
router.get('/user', userController.getUserDetails);

module.exports = router;
