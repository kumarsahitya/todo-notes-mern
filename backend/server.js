const express = require("express");
const crypto = require("crypto");
const mailSender = require("./src/utils/mailSender");
const app = express();

require("dotenv").config();
const PORT = process.env.PORT || 4000;

// json
app.use(express.json());

// cors
app.use((req, res, next) => {
	res.setHeader("Access-Control-Allow-Origin", "*");
	res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
	res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
	next();
});

// test api
app.get("/test", (req, res) => {
	try {
		res.status(200).json({ message: "API is working" });
		sendVerificationEmail(req, "test@example.com");
	} catch (error) {
		res.status(500).json({ message: error.message });
	}
});

// Define a function to send emails
async function sendVerificationEmail(req, email) {
	// Send the email using our custom mailSender Function
	try {
		let login_url = "http://" + req.headers.host + "/login/";
		let action_url =
			"http://" +
			req.headers.host +
			"/confirmation/" +
			email +
			"/" +
			crypto.randomBytes(16).toString("hex");
		const mailResponse = await mailSender(
			email,
			"Verification Email",
			"emailVerification",
			{
				first_name: "Test",
				last_name: "User",
				email: email,
				login_url: login_url,
				action_url: action_url,
			}
		);
		console.log("Email sent successfully: ", mailResponse);
	} catch (error) {
		console.log("Error occurred while sending email: ", error);
		throw error;
	}
}

app.listen(PORT, () => {
	console.log(`Server Started on port ${PORT}`);
});
