import logger from '../../helpers/logger.js';
import mailSender from '../../utils/mailSender.js';
import dotenv from 'dotenv'


dotenv.config();

/**
 * Sends a verification email to the user.
 *
 * @param {Object} req - The request object.
 * @param {Object} userInstance - The user instance.
 * @param {Object} userAttributeInstance - The user attribute instance.
 * @return {Promise<Object>} The response from the mailSender function.
 * @throws {Error} If an error occurs while sending the email.
 */
export const sendVerificationEmail = async (
	req,
	userInstance,
	userAttributeInstance
) => {
	// Send the email using our custom mailSender Function
	try {
		// TODO: Change action url to be front-end url
		const login_url = 'http://' + req.headers.host + '/login/';
		const action_url =
			'http://' +
			req.headers.host +
			'/api/v1/auth/confirmation/' +
			userInstance.email +
			'/' +
			userAttributeInstance.email_verify_token;
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
			}
		);
		return mailResponse;
	} catch (error) {
		logger.error('Error occurred while sending email: ', error);
		throw error;
	}
};

/**
 * Sends a request reset password email to the user.
 *
 * @param {Object} req - The request object.
 * @param {Object} userInstance - The user instance.
 * @param {string} resetToken - The reset token.
 * @return {Promise<Object>} The response from the mailSender function.
 * @throws {Error} If an error occurs while sending the email.
 */
export const sendRequestResetPasswordEmail = async (
	req,
	userInstance,
	resetToken
) => {
	// Send the email using our custom mailSender Function
	try {
		// TODO: Change action url to be front-end url
		const login_url = 'http://' + req.headers.host + '/login/';
		const action_url =
			'http://' +
			req.headers.host +
			'/api/v1/auth/resetPassword/' +
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
			}
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
 * @return {Promise<Object>} The response from the mailSender function.
 * @throws {Error} If an error occurs while sending the email.
 */
export const sendResetPasswordEmail = async (req, userInstance) => {
	// Send the email using our custom mailSender Function
	try {
		// TODO: Change action url to be front-end url
		const login_url = 'http://' + req.headers.host + '/login/';
		const action_url = login_url;
		const mailResponse = await mailSender(
			userInstance.email,
			'Password Reset Successfully',
			'resetPassword',
			{
				first_name: userInstance.first_name,
				last_name: userInstance.last_name,
				email: userInstance.email,
				login_url,
				action_url,
			}
		);
		return mailResponse;
	} catch (error) {
		logger.error('Error occurred while sending email: ', error);
		throw error;
	}
};
