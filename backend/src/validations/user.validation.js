const Models = require('../models');
const { body, param } = require('express-validator');
const singupRules = [
	body('first_name')
		.exists({ checkFalsy: true })
		.withMessage('First name is required')
		.isString()
		.withMessage('First name should be string'),
	body('last_name')
		.exists({ checkFalsy: true })
		.withMessage('First name is required')
		.isString()
		.withMessage('First name should be string'),
	body('email')
		.exists({ checkFalsy: true })
		.isEmail()
		.withMessage('Provide valid email')
		.custom(async (value) => {
			const user = await Models['User'].findOne({ email: value });
			if (user) {
				throw new Error('A user already exists with this e-mail address');
			}
		}),
	body('password')
		.exists({ checkFalsy: true })
		.withMessage('Password is required')
		.isString()
		.withMessage('Password should be string')
		.isStrongPassword({
			minlength: 8,
			minLowercase: 1,
			minUppercase: 1,
			minNumbers: 1,
			minSymbols: 1,
		}),
	body('confirmed_password')
		.exists({ checkFalsy: true })
		.withMessage('You must type a confirmation password')
		.custom((value, { req }) => value === req.body.password)
		.withMessage('The passwords do not match'),

	body('phone')
		.optional()
		.isString()
		.withMessage('phone number should be string'),
];

const loginRules = [
	body('email')
		.exists({ checkFalsy: true })
		.withMessage('Email is required')
		.isEmail()
		.withMessage('Provide valid email'),
	body('password')
		.exists({ checkFalsy: true })
		.withMessage('Password is required'),
];

const confirmationRules = [
	param('email')
		.exists({ checkFalsy: true })
		.withMessage('Email is required')
		.isEmail()
		.withMessage('Provide valid email'),
	param('token').exists({ checkFalsy: true }).withMessage('Token is required'),
];
module.exports = { singupRules, loginRules, confirmationRules };
