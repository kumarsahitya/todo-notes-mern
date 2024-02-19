const mailSender = require('../../utils/mailSender');

require('dotenv').config();
// Define a function to send emails
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
        console.log('Error occurred while sending email: ', error);
        throw error;
    }
};
