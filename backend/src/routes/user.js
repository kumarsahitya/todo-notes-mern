import express from 'express';
const router = express.Router();

import validation from '../validations/user.validation.js';

// Handlers from controllers
import user from '../controllers/user.js'; // API created using mongoose

import authMiddle from '../middlewares/authMiddle.js';

router.post('/login', validation.loginRules, user.login);
router.post('/signup', validation.singupRules, user.signup);
router.get(
	'/confirmation/:email/:token',
	validation.confirmationRules,
	user.confirmation
);
router.post(
	'/forgotPassword',
	validation.forgotPasswordRules,
	user.forgotPassword
);
router.post(
	'/resetPassword',
	validation.resetPasswordRules,
	user.resetPassword
);
router.post(
	'/changePassword',
	authMiddle.auth,
	validation.changePasswordRules,
	user.changePassword
);
router.get('/profile', authMiddle.auth, user.profile);

// testing protected route
router.get('/test', authMiddle.auth, (req, res) => {
	res.json({
		success: true,
		message: 'You are a valid Tester.',
	});
});
// protected routes
router.get('/user', authMiddle.auth, authMiddle.isUser, (req, res) => {
	res.json({
		success: true,
		message: 'You are a valid Student.',
	});
});

router.get('/admin', authMiddle.auth, authMiddle.isAdmin, (req, res) => {
	res.json({
		success: true,
		message: 'You are a valid Admin.',
	});
});

export default router;
