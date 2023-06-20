const express = require('express')
const router = express.Router()
const {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
  getUsers,
  loginStatus,
  upgradeUser,
  sendAutomatedEmail,
  sendVerificationEmail,
  verifyUser,
  forgotPassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle,
} = require('../controllers/userController')
const {
  protect,
  adminOnly,
  authorOnly,
} = require('../middleware/authMiddleware')

// User Routes
router.post('/register', registerUser)
router.post('/login', loginUser)
router.get('/logout', logoutUser)
router.get('/get-user', protect, getUser)
router.patch('/update-user', protect, updateUser)

router.delete('/:id', protect, adminOnly, deleteUser)
router.get('/get-users', protect, authorOnly, getUsers)
router.get('/login-status', loginStatus)
router.post('/upgrade-user', protect, adminOnly, upgradeUser)
router.post('/send-automated-email', protect, sendAutomatedEmail)

router.post('/send-verification-email', protect, sendVerificationEmail)
router.patch('/verify-user/:verificationToken', verifyUser)
router.post('/forgot-password', forgotPassword)
router.patch('/reset-password/:resetToken', resetPassword)
router.patch('/change-password', protect, changePassword)

router.post('/send-login-code/:email', sendLoginCode)
router.post('/login-with-code/:email', loginWithCode)

router.post('/google/callback', loginWithGoogle)

module.exports = router
