const bcrypt = require('bcrypt');
const User = require('../models/User');
const Token = require('../models/Token');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { validationResult } = require('express-validator');
const {
	sendVerificationEmail,
	sendRequestResetPasswordEmail,
	sendResetPasswordEmail,
} = require('./traits/user');
const logger = require('../helpers/logger');
require('dotenv').config();

/**
 * Handles the signup process for a new user.
 *
 * @param {Object} req - The request object containing user data.
 * @param {Object} res - The response object to send the signup status.
 * @return {Promise<void>} The function does not return anything.
 */
exports.signup = async (req, res) => {
	try {
		const errors = validationResult(req);

		// if there is error then return Error
		if (!errors.isEmpty()) {
			return res.status(403).json({
				success: false,
				errors: errors.array(),
			});
		}

		// get input data
		const { first_name, last_name, email, password, phone } = req.body;

		const emailToken = await crypto.randomBytes(16).toString('hex');
		const userData = {
			first_name,
			last_name,
			email,
			password,
			phone,
			email_verify_token: emailToken,
			role: 'User',
		};

		// Using mongoose: to create new user
		const userInstance = await User.create(userData);

		// sending email for verification
		userInstance.password = undefined;
		try {
			if (await sendVerificationEmail(req, userInstance)) {
				return res.status(200).json({
					success: true,
					message: `A verification email has been sent to ${userInstance.email}.`,
					data: { user: userInstance },
				});
			}
		} catch (error) {
			return res.status(500).json({
				success: false,
				message: `Error occurred while sending email: ${error.message}`,
			});
		}

		// Sending a success response
		return res.status(200).json({
			success: true,
			message: 'user created successfully.',
			data: { user: userInstance },
		});
	} catch (error) {
		// Logging & sending an error response
		logger.error(error);
		return res.status(500).json({
			success: false,
			message: `User registration failed: ${error.message}`,
		});
	}
};

/**
 * Logs in a user.
 *
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @return {Promise<void>} The function does not return anything.
 */
exports.login = async (req, res) => {
	try {
		const errors = validationResult(req);

		// if there is error then return Error
		if (!errors.isEmpty()) {
			return res.status(403).json({
				success: false,
				errors: errors.array(),
			});
		}

		// data fetch
		const { email, password } = req.body;

		// Using mongoose: check for registered User
		let userInstance = await User.findOne({ email });

		// if user not registered or not found in database
		if (!userInstance) {
			return res.status(401).json({
				success: false,
				message: 'You have to Signup First',
			});
		}

		// validate user is active and verified email
		if (!userInstance.active) {
			return res.status(401).json({
				success: false,
				message:
					'You account has been inactive. Please contact admin or verify email address first',
			});
		}
		if (!userInstance.email_verified) {
			try {
				const emailToken = await crypto.randomBytes(16).toString('hex');
				userInstance.email_verify_token = emailToken;
				if (await userInstance.save()) {
					await sendVerificationEmail(req, userInstance);
				}
			} catch (error) {}
			return res.status(401).json({
				success: false,
				message:
					'Unable to login into your account. Please verify email address first',
			});
		}

		const payload = {
			email: userInstance.email,
			id: userInstance._id,
			role: userInstance.role,
		};
		// verify password and generate a JWt token 🔎
		if (await bcrypt.compare(password, userInstance.password)) {
			// if password matched
			// now lets create a JWT token
			const token = jwt.sign(payload, process.env.JWT_SECRET, {
				expiresIn: process.env.JWT_EXPIRES_IN,
			});
			userInstance = userInstance.toObject();
			// userInstance.token = token;

			userInstance.password = undefined;
			const options = {
				expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
				httpOnly: true, // It will make cookie not accessible on clinet side -> good way to keep hackers away
			};

			// Sending a success response
			res.cookie('token', token, options)
				.status(200)
				.json({
					success: true,
					message: 'Your password has been changed Successfully.',
					data: { token, user: userInstance },
				});
		} else {
			// password donot matched
			return res.status(403).json({
				success: false,
				message: 'Password incorrects!',
			});
		}
	} catch (error) {
		// Logging & sending an error response
		logger.error(error);
		res.status(500).json({
			success: false,
			message: `Login failure: ${error.message}`,
		});
	}
};

/**
 * Handles the email verification process for a user.
 *
 * @param {Object} req - The request object containing email and token parameters.
 * @param {Object} res - The response object to send the verification status.
 * @return {Promise<void>} The function does not return anything.
 */
exports.confirmation = async (req, res) => {
	try {
		const errors = validationResult(req);

		// if there is error then return Error
		if (!errors.isEmpty()) {
			return res.status(403).json({
				success: false,
				errors: errors.array(),
			});
		}

		// data fetch
		const { email, token } = req.params;

		// Using mongoose: check for registered User
		const userInstance = await User.findOne({
			email,
			email_verify_token: token,
		});
		// if user not registered or not found in database
		if (!userInstance) {
			return res.status(401).json({
				success: false,
				message: 'You have to Signup First',
			});
		}
		// user is already verified
		else if (userInstance.email_verified) {
			return res.status(200).json({
				success: true,
				message: 'Your email has been already verified. Please Login',
			});
		} else {
			// Using mongoose: change isVerified to true and mark active
			userInstance.active = true;
			userInstance.email_verified = true;
			userInstance.email_verify_token = null;
			const updateUser = await userInstance.save();
			if (updateUser) {
				return res.status(200).json({
					success: true,
					message: 'Your account has been successfully verified',
				});
			} else {
				return res.status(500).json({
					success: false,
					message: 'Unable to verify your email address',
				});
			}
		}
	} catch (error) {
		// Logging & sending an error response
		logger.error(error);
		res.status(500).json({
			success: false,
			message: `Email Verification failed: ${error.message}`,
		});
	}
};

/**
 * Handles the change password process for a user.
 *
 * @param {Object} req - The request object containing user data.
 * @param {Object} res - The response object to send the password change status.
 * @return {Promise<void>} The function does not return anything.
 */
exports.changePassword = async (req, res) => {
	try {
		const errors = validationResult(req);

		// if there is error then return Error
		if (!errors.isEmpty()) {
			return res.status(403).json({
				success: false,
				errors: errors.array(),
			});
		}

		// data fetch
		const { password, new_password } = req.body;

		// Using mongoose: check for registered User
		let userInstance = await User.findOne({
			email: req.loggedInUser.email,
		});

		// if user not registered or not found in database
		if (!userInstance) {
			return res.status(401).json({
				success: false,
				message: 'You have to Signup First',
			});
		}

		// validate user is active and verified email
		if (!userInstance.active) {
			return res.status(401).json({
				success: false,
				message:
					'You account has been inactive. Please contact admin or verify email address first',
			});
		}

		// verify password and generate a JWt token 🔎
		if (await bcrypt.compare(password, userInstance.password)) {
			// if password matched
			// now lets change it to new password & save it to database
			userInstance.password = new_password;
			await userInstance.save();

			userInstance = userInstance.toObject();
			userInstance.password = undefined;

			// Sending a success response
			res.status(200).json({
				success: true,
				message: 'Your password has been changes Successfully.',
				data: { user: userInstance },
			});
		} else {
			// password donot matched
			return res.status(403).json({
				success: false,
				message: 'Password incorrects!',
			});
		}
	} catch (error) {
		// Logging & sending an error response
		logger.error(error);
		res.status(500).json({
			success: false,
			message: `Change Password failed: ${error.message}`,
		});
	}
};

/**
 * Handles the forgot password process for a user.
 *
 * @param {Object} req - The request object containing user data.
 * @param {Object} res - The response object to send the forgot password status.
 * @return {Promise<void>} The function does not return anything.
 */
exports.forgotPassword = async (req, res) => {
	try {
		const errors = validationResult(req);

		// if there is error then return Error
		if (!errors.isEmpty()) {
			return res.status(403).json({
				success: false,
				errors: errors.array(),
			});
		}

		// data fetch
		const { email } = req.body;

		// Using mongoose: check for registered User
		let userInstance = await User.findOne({ email });

		// if user not registered or not found in database
		if (!userInstance) {
			return res.status(401).json({
				success: false,
				message: 'You have to Signup First',
			});
		}

		// validate user is active and verified email
		if (!userInstance.active) {
			return res.status(401).json({
				success: false,
				message:
					'You account has been inactive. Please contact admin or verify email address first',
			});
		}

		// find token if exist, delete it, then create a new one
		let token = await Token.findOne({ userId: userInstance._id });
		if (token) await token.deleteOne();
		let resetToken = crypto.randomBytes(32).toString('hex');
		const hash = await bcrypt.hash(
			resetToken,
			Number(process.env.BCRYPT_SALT),
		);

		// save new token in database and send email
		await new Token({
			userId: userInstance._id,
			token: hash,
			createdAt: Date.now(),
		}).save();

		try {
			await sendRequestResetPasswordEmail(req, userInstance, resetToken);
		} catch (error) {
			throw error;
		}

		// Sending a success response
		res.status(200).json({
			success: true,
			message: 'Password reset link sent to your email account.',
		});
	} catch (error) {
		// Logging & sending an error response
		logger.error(error);
		res.status(500).json({
			success: false,
			message: `Forgot Password failed: ${error.message}`,
		});
	}
};

/**
 * Resets the password for a user.
 *
 * @param {Object} req - The request object containing user data.
 * @param {Object} res - The response object to send the password reset status.
 * @return {Promise<void>} The function does not return anything.
 */
exports.resetPassword = async (req, res) => {
	try {
		const errors = validationResult(req);

		// if there is error then return Error
		if (!errors.isEmpty()) {
			return res.status(403).json({
				success: false,
				errors: errors.array(),
			});
		}

		// data fetch
		const { userId, token, password } = req.body;

		// Using mongoose: check for registered User
		let userInstance = await User.findOne({ _id: userId });

		// if user not registered or not found in database
		if (!userInstance) {
			return res.status(401).json({
				success: false,
				message: 'You have to Signup First',
			});
		}

		// fetch token by userId and validate it
		let resetPasswordToken = await Token.findOne({ userId });
		if (!resetPasswordToken) {
			return res.status(401).json({
				success: false,
				message: 'Invalid or expired password reset token',
			});
		}
		const isValid = await bcrypt.compare(token, resetPasswordToken.token);
		if (!isValid) {
			return res.status(401).json({
				success: false,
				message: 'Invalid or expired password reset token',
			});
		}

		userInstance.password = password;
		await userInstance.save();

		try {
			await sendResetPasswordEmail(req, userInstance);
		} catch (error) {
			throw error;
		}

		// Sending a success response
		res.status(200).json({
			success: true,
			message: 'Password reset sucessfully.',
		});
	} catch (error) {
		// Logging & sending an error response
		logger.error(error);
		res.status(500).json({
			success: false,
			message: `Forgot Password failed: ${error.message}`,
		});
	}
};

/**
 * Retrieves the profile of a registered user.
 *
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @return {Promise<void>} The promise that resolves when the profile is retrieved successfully or rejects with an error.
 */
exports.profile = async (req, res) => {
	try {
		// Using mongoose: check for registered User
		let userInstance = await User.findOne({
			email: req.loggedInUser.email,
		});

		// if user not registered or not found in database
		if (!userInstance) {
			return res.status(401).json({
				success: false,
				message: 'You have to Signup First',
			});
		}
		userInstance.password = undefined;

		// Sending a success response
		res.status(200).json({
			success: true,
			message: 'Profile fetch sucessfully.',
			data: { user: userInstance },
		});
	} catch (error) {
		// Logging & sending an error response
		logger.error(error);
		res.status(500).json({
			success: false,
			message: `Forgot Password failed: ${error.message}`,
		});
	}
};
