const logger = require('../../helpers/logger');
const mailSender = require('../../utils/mailSender');

require('dotenv').config();

/**
 * Sends a verification email to the user.
 *
 * @param {Object} req - The request object.
 * @param {Object} userInstance - The user instance.
 * @return {Promise<Object>} The response from the mailSender function.
 * @throws {Error} If an error occurs while sending the email.
 */
exports.sendVerificationEmail = async (req, userInstance) => {
	// Send the email using our custom mailSender Function
	try {
		const login_url = 'http://' + req.headers.host + '/login/';
		const action_url =
			'http://' +
			req.headers.host +
			'/api/v1/auth/confirmation/' +
			userInstance.email +
			'/' +
			userInstance.email_verify_token;
		const mailResponse = await mailSender(
			userInstance.email,
			'Verification Email',
			'emailVerification',
			{
				first_name: userInstance.first_name,
				last_name: userInstance.last_name,
				email: userInstance.email,
				login_url,
				action_url,
			},
		);
		return mailResponse;
	} catch (error) {
		logger.error('Error occurred while sending email: ', error);
		throw error;
	}
};

/**
 * Sends a reset password email to the user.
 *
 * @param {Object} req - The request object.
 * @param {Object} userInstance - The user instance.
 * @param {string} resetToken - The reset token.
 * @return {Promise<Object>} The response from the mailSender function.
 * @throws {Error} If an error occurs while sending the email.
 */
exports.sendResetPasswordEmail = async (req, userInstance, resetToken) => {
	// Send the email using our custom mailSender Function
	try {
		const login_url = 'http://' + req.headers.host + '/login/';
		const action_url =
			'http://' +
			req.headers.host +
			'/api/v1/auth/passwordReset/' +
			userInstance._id +
			'/' +
			resetToken;
		const mailResponse = await mailSender(
			userInstance.email,
			'Password Reset Request',
			'requestResetPassword',
			{
				first_name: userInstance.first_name,
				last_name: userInstance.last_name,
				email: userInstance.email,
				login_url,
				action_url,
			},
		);
		return mailResponse;
	} catch (error) {
		logger.error('Error occurred while sending email: ', error);
		throw error;
	}
};
