const express = require('express');
const router = express.Router();
const {
	singupRules,
	loginRules,
	confirmationRules,
	changePasswordRules,
	forgotPasswordRules,
	resetPasswordRules,
} = require('../validations/user.validation');

// Handlers from controllers
const {
	login,
	signup,
	confirmation,
	changePassword,
	forgotPassword,
	resetPassword,
	profile,
} = require('../controllers/user'); // API created using mongoose
// const { login, signup, confirmation } = require("../controllers/prisma/auth"); // API created using prisma
const { auth, isUser, isAdmin } = require('../middlewares/authMiddle');

router.post('/login', loginRules, login);
router.post('/signup', singupRules, signup);
router.get('/confirmation/:email/:token', confirmationRules, confirmation);
router.post('/forgotPassword', forgotPasswordRules, forgotPassword);
router.post('/resetPassword', resetPasswordRules, resetPassword);
router.post('/changePassword', auth, changePasswordRules, changePassword);
router.get('/profile', auth, profile);

// testing protected route
router.get('/test', auth, (req, res) => {
	res.json({
		success: true,
		message: 'You are a valid Tester.',
	});
});
// protected routes
router.get('/user', auth, isUser, (req, res) => {
	res.json({
		success: true,
		message: 'You are a valid Student.',
	});
});

router.get('/admin', auth, isAdmin, (req, res) => {
	res.json({
		success: true,
		message: 'You are a valid Admin.',
	});
});

module.exports = router;
