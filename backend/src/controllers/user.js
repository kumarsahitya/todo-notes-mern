const bcrypt = require('bcrypt');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { validationResult } = require('express-validator');
const { sendVerificationEmail } = require('./traits/user');
const logger = require('../helpers/logger');
require('dotenv').config();

// signup handle
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

		// sending email for verification
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

		// Using mongoose
		const userInstance = await User.create(userData);

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

		return res.status(200).json({
			success: true,
			message: 'user created successfully.',
			data: { user: userInstance },
		});
	} catch (error) {
		logger.error(error);
		return res.status(500).json({
			success: false,
			message: `User registration failed: ${error.message}`,
		});
	}
};

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

		// check for registered User
		// Using mongoose
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
			res
				.cookie('token', token, options)
				.status(200)
				.json({
					success: true,
					message: 'Logged in Successfully.',
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
		logger.error(error);
		res.status(500).json({
			success: false,
			message: `Login failure: ${error.message}`,
		});
	}
};

// It is GET method, you have to write like that
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

		// check for registered User
		// Using mongoose
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
			// change isVerified to true and mark active
			// Using mongoose
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
		logger.error(error);
		res.status(500).json({
			success: false,
			message: `Email Verification failed: ${error.message}`,
		});
	}
};
