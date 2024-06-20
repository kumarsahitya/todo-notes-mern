import bcrypt from 'bcrypt';
import User from '../models/User';
import Token from '../models/Token';
import UserAttribute from '../models/UserAttribute';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { validationResult } from 'express-validator';

import {
	sendVerificationEmail,
	sendRequestResetPasswordEmail,
	sendResetPasswordEmail,
} from './traits/user';

import logger from '../helpers/logger';
require('dotenv').config();

export default {
	/**
	 * Handles the signup process for a new user.
	 *
	 * @param {Object} req - The request object containing user data.
	 * @param {Object} res - The response object to send the signup status.
	 * @return {Promise<void>} The function does not return anything.
	 */
	signup: async (req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return res.status(403).json({
					success: false,
					errors: errors.array(),
				});
			}

			let userInstance = await createUser(req);
			let userAttributeInstance =
				await createUserAttributeInstance(userInstance);
			const emailToken = await crypto.randomBytes(16).toString('hex');
			userAttributeInstance.email_verify_token = emailToken;
			await userAttributeInstance.save();

			userInstance = userInstance.toObject();
			userInstance.password = undefined;

			// sending email for verification
			try {
				if (
					await sendVerificationEmail(
						req,
						userInstance,
						userAttributeInstance,
					)
				) {
					return res.status(200).json({
						success: true,
						message: `A verification email has been sent to ${userInstance.email}.`,
						data: { user: userInstance },
					});
				}
			} catch (error) {
				return await logError(
					error,
					`Error occurred while sending email: ${error.message}`,
					res,
				);
			}

			// Sending a success response
			return res.status(200).json({
				success: true,
				message: 'user created successfully.',
				data: { user: userInstance },
			});
		} catch (error) {
			return await logError(
				error,
				`User registration failed: ${error.message}`,
				res,
			);
		}
	},

	/**
	 * Logs in a user.
	 *
	 * @param {Object} req - The request object.
	 * @param {Object} res - The response object.
	 * @return {Promise<void>} The function does not return anything.
	 */
	login: async (req, res) => {
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

			let userAttributeInstance =
				await createUserAttributeInstance(userInstance);

			if (!userAttributeInstance.email_verified) {
				return await sendVerificationEmailIfNotVerified(
					req,
					res,
					userInstance,
					userAttributeInstance,
				);
			}
			// verify password and generate a JWt token 🔎
			if (await bcrypt.compare(password, userInstance.password)) {
				// if password matched
				// now lets create a JWT token
				const token = await generateJwtToken(userInstance);

				userAttributeInstance.last_login_at = new Date();
				await userAttributeInstance.save();

				userInstance = userInstance.toObject();
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
			return await logError(
				error,
				`Login failure: ${error.message}`,
				res,
			);
		}
	},

	/**
	 * Handles the email verification process for a user.
	 *
	 * @param {Object} req - The request object containing email and token parameters.
	 * @param {Object} res - The response object to send the verification status.
	 * @return {Promise<void>} The function does not return anything.
	 */
	confirmation: async (req, res) => {
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
			});

			// get user attributes
			let userAttributeInstance = await UserAttribute.findOne({
				user_id: userInstance._id,
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
			else if (userAttributeInstance.email_verified) {
				return res.status(200).json({
					success: true,
					message:
						'Your email has been already verified. Please Login',
				});
			} else {
				// Using mongoose: change isVerified to true and mark active
				userAttributeInstance.email_verified = true;
				userAttributeInstance.email_verify_token = null;
				await userAttributeInstance.save();

				userInstance.active = true;
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
			return await logError(
				error,
				`Email Verification failed: ${error.message}`,
				res,
			);
		}
	},

	/**
	 * Handles the change password process for a user.
	 *
	 * @param {Object} req - The request object containing user data.
	 * @param {Object} res - The response object to send the password change status.
	 * @return {Promise<void>} The function does not return anything.
	 */
	changePassword: async (req, res) => {
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

			let userAttributeInstance =
				await createUserAttributeInstance(userInstance);

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

				userAttributeInstance.password_updated = new Date();
				await userAttributeInstance.save();

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
			return await logError(
				error,
				`Change Password failed: ${error.message}`,
				res,
			);
		}
	},

	/**
	 * Handles the forgot password process for a user.
	 *
	 * @param {Object} req - The request object containing user data.
	 * @param {Object} res - The response object to send the forgot password status.
	 * @return {Promise<void>} The function does not return anything.
	 */
	forgotPassword: async (req, res) => {
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

			await sendRequestResetPasswordEmail(req, userInstance, resetToken);

			// Sending a success response
			res.status(200).json({
				success: true,
				message: 'Password reset link sent to your email account.',
			});
		} catch (error) {
			return await logError(
				error,
				`Forgot Password failed: ${error.message}`,
				res,
			);
		}
	},

	/**
	 * Resets the password for a user.
	 *
	 * @param {Object} req - The request object containing user data.
	 * @param {Object} res - The response object to send the password reset status.
	 * @return {Promise<void>} The function does not return anything.
	 */
	resetPassword: async (req, res) => {
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

			let userAttributeInstance =
				await createUserAttributeInstance(userInstance);

			// fetch token by userId and validate it
			let resetPasswordToken = await Token.findOne({ userId });
			if (!resetPasswordToken) {
				return res.status(401).json({
					success: false,
					message: 'Invalid or expired password reset token',
				});
			}
			const isValid = await bcrypt.compare(
				token,
				resetPasswordToken.token,
			);
			if (!isValid) {
				return res.status(401).json({
					success: false,
					message: 'Invalid or expired password reset token',
				});
			}

			userInstance.password = password;
			await userInstance.save();

			userAttributeInstance.password_updated = new Date();
			await userAttributeInstance.save();

			await sendResetPasswordEmail(req, userInstance);

			// Sending a success response
			res.status(200).json({
				success: true,
				message: 'Password reset sucessfully.',
			});
		} catch (error) {
			return await logError(
				error,
				`Reset Password failed: ${error.message}`,
				res,
			);
		}
	},

	/**
	 * Retrieves the profile of a registered user.
	 *
	 * @param {Object} req - The request object.
	 * @param {Object} res - The response object.
	 * @return {Promise<void>} The promise that resolves when the profile is retrieved successfully or rejects with an error.
	 */
	profile: async (req, res) => {
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
			userInstance = userInstance.toObject();
			userInstance.password = undefined;

			// Sending a success response
			res.status(200).json({
				success: true,
				message: 'Profile fetch sucessfully.',
				data: { user: userInstance },
			});
		} catch (error) {
			return await logError(
				error,
				`Forgot Password failed: ${error.message}`,
				res,
			);
		}
	},

	/**
	 * Creates a user attribute instance for a given user instance if it doesn't already exist.
	 *
	 * @param {Object} userInstance - The user instance for which to create the attribute.
	 * @return {Promise<Object>} The created user attribute instance.
	 * @throws {Error} If an error occurs during the creation process.
	 */
	createUserAttributeInstance: async (userInstance) => {
		try {
			// get user attributes
			let userAttributeInstance = await UserAttribute.findOne({
				user_id: userInstance._id,
			});

			// if user attribute not found in database
			if (!userAttributeInstance) {
				var attributeObj = {
					user_id: userInstance._id,
				};
				userAttributeInstance =
					await UserAttribute.create(attributeObj);
				userInstance.user_attribute_id = userAttributeInstance._id;
				await userInstance.save();
			}

			return userAttributeInstance;
		} catch (error) {
			throw error;
		}
	},

	/**
	 * Sends a verification email if the user's email address has not been verified.
	 *
	 * @param {Object} req - The request object.
	 * @param {Object} res - The response object.
	 * @param {Object} userInstance - The user instance.
	 * @param {Object} userAttributeInstance - The user attribute instance.
	 * @return {Object} The response object with a status code and JSON data.
	 */
	sendVerificationEmailIfNotVerified: async (
		req,
		res,
		userInstance,
		userAttributeInstance,
	) => {
		if (!userAttributeInstance.email_verified) {
			try {
				const emailToken = await crypto.randomBytes(16).toString('hex');
				userAttributeInstance.email_verify_token = emailToken;
				if (await userAttributeInstance.save()) {
					await sendVerificationEmail(
						req,
						userInstance,
						userAttributeInstance,
					);
				}
			} catch (error) {}
			return res.status(401).json({
				success: false,
				message:
					'Unable to login into your account. Please verify email address first',
			});
		}
	},

	/**
	 * Generates a JSON Web Token (JWT) for the given user instance.
	 *
	 * @param {Object} userInstance - The user instance for which the JWT is generated.
	 * @return {Promise<string>} The generated JWT.
	 * @throws {Error} If there is an error during the token generation process.
	 */
	generateJwtToken: async (userInstance) => {
		try {
			const payload = {
				email: userInstance.email,
				id: userInstance._id,
				role: userInstance.role,
			};
			const token = jwt.sign(payload, process.env.JWT_SECRET, {
				expiresIn: process.env.JWT_EXPIRES_IN,
			});
			return token;
		} catch (error) {
			throw error;
		}
	},

	/**
	 * Creates a new user using the provided input data.
	 *
	 * @param {Object} req - The request object containing the input data.
	 * @param {Object} res - The response object to send the result to.
	 * @return {Promise<Object>} A promise that resolves to the created user object.
	 */
	createUser: async (req, res) => {
		// get input data
		const { first_name, last_name, email, password, phone } = req.body;
		const userData = {
			first_name,
			last_name,
			email,
			password,
			phone,
			role: 'User',
		};

		// Using mongoose: to create new user
		return await User.create(userData);
	},

	/**
	 * Logs an error and sends an error response.
	 *
	 * @param {Error} error - The error object to log.
	 * @param {string} message - The error message to include in the response.
	 * @param {Object} res - The response object to send the error response to.
	 * @return {Promise<Object>} The error response object.
	 */
	logError: async (error, message, res) => {
		// Logging & sending an error response
		logger.error(error);
		return res.status(500).json({
			success: false,
			message: message,
		});
	},
};
