import express from 'express';
const router = express.Router();

import {
	singupRules,
	loginRules,
	confirmationRules,
	changePasswordRules,
	forgotPasswordRules,
	resetPasswordRules,
} from '../validations/user.validation';

// Handlers from controllers
import {
	login,
	signup,
	confirmation,
	changePassword,
	forgotPassword,
	resetPassword,
	profile,
} from '../controllers/user'; // API created using mongoose

import { auth, isUser, isAdmin } from '../middlewares/authMiddle';

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

export default router;
