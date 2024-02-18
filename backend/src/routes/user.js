const express = require("express");
const router = express.Router();

//Handlers from controllers
const { login, signup } = require("../controllers/auth");
const { auth, isUser, isAdmin } = require("../middlewares/authMiddle");

router.post("/login", login);
router.post("/signup", signup);

//testing protected route
router.get("/test", auth, (req, res) => {
	res.json({
		success: true,
		message: "You are a valid Tester.",
	});
});
//protected routes
router.get("/user", auth, isUser, (req, res) => {
	res.json({
		success: true,
		message: "You are a valid Student.",
	});
});

router.get("/admin", auth, isAdmin, (req, res) => {
	res.json({
		success: true,
		message: "You are a valid Admin.",
	});
});

module.exports = router;
