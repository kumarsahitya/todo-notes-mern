const jwt = require('jsonwebtoken');
const logger = require('../helpers/logger');
const User = require('../models/User');
require('dotenv').config();

// auth, isUser, isAdmin

exports.auth = async (req, res, next) => {
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
};

exports.isUser = (req, res, next) => {
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
};

exports.isAdmin = (req, res, next) => {
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
};
