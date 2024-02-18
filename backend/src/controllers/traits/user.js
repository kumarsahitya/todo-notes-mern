const mailSender = require("../../utils/mailSender");

require("dotenv").config();
// Define a function to send emails
exports.sendVerificationEmail = async (req, User) => {
	// Send the email using our custom mailSender Function
	try {
		let login_url = "http://" + req.headers.host + "/login/";
		let action_url =
			"http://" +
			req.headers.host +
			"/confirmation/" +
			User.email +
			"/" +
			User.email_verify_token;
		const mailResponse = await mailSender(
			User.email,
			"Verification Email",
			"emailVerification",
			{
				...User,
				login_url: login_url,
				action_url: action_url,
			}
		);
	} catch (error) {
		console.log("Error occurred while sending email: ", error);
		throw error;
	}
};
