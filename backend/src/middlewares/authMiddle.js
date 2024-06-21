import jwt from 'jsonwebtoken';
import logger from '../helpers/logger.js';
import User from '../models/User.js';
import dotenv from 'dotenv';
dotenv.config();

// auth, isUser, isAdmin

export default {
	/**
	 * Middleware function to authenticate the user.
	 *
	 * @param {Object} req - The request object.
	 * @param {Object} res - The response object.
	 * @param {Function} next - The next middleware function.
	 * @return {Promise<void>} - Returns a promise that resolves when the middleware is done.
	 */
	auth: async (req, res, next) => {
		try {
			// extract JWT token
			let token = req.header('Authorization');

			if (!token) {
				return res.status(401).json({
					success: false,
					message: 'Token Missing',
				});
			}

			token = token.split(' ')[1]; // Remove Bearer from string
			if (token === 'null' || !token)
				return res.status(401).send('Unauthorized request');

			// verify the token
			try {
				const decode = jwt.verify(token, process.env.JWT_SECRET);
				const user = await User.findById(decode.id);
				req.loggedInUser = user;
			} catch (error) {
				return res.status(401).json({
					success: false,
					message: 'invalid Token',
				});
			}

			next();
		} catch (error) {
			logger.error(error);
			return res.status(401).json({
				success: false,
				message: 'Error Occured in Authentication.',
			});
		}
	},

	/**
	 * Middleware function to check if the logged in user is an admin.
	 *
	 * @param {Object} req - The request object.
	 * @param {Object} res - The response object.
	 * @param {Function} next - The next middleware function.
	 * @return {Promise<void>} - Returns a promise that resolves when the middleware is done.
	 */
	isUser: (req, res, next) => {
		try {
			if (req.loggedInUser.role !== 'User') {
				return res.status(401).json({
					success: false,
					message: 'You are not authorized User!',
				});
			}

			next();
		} catch (error) {
			return res.status(500).json({
				success: false,
				message: 'Something error occured: ' + error,
			});
		}
	},

	/**
	 * Middleware function to check if the logged in user is an admin.
	 *
	 * @param {Object} req - The request object.
	 * @param {Object} res - The response object.
	 * @param {Function} next - The next middleware function.
	 * @return {Promise<void>} - Returns a promise that resolves when the middleware is done.
	 */
	isAdmin: (req, res, next) => {
		try {
			if (req.loggedInUser.role !== 'Admin') {
				return res.status(401).json({
					success: false,
					message: 'You are not authorized Admin!',
				});
			}

			next();
		} catch (error) {
			return res.status(500).json({
				success: false,
				message: 'Something error occured: ' + error,
			});
		}
	},
};
