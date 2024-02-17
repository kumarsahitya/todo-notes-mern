const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
	first_name: { type: String, required: true, default: "", trim: true },
	last_name: { type: String, required: true, default: "", trim: true },
	email: { type: String, unique: true, required: true, index: true },
	email_verified: { type: Boolean, default: false },
	email_verify_token: { type: String, default: null },
	phone: { type: String, default: "" },
	avatar: { type: String, default: "" },
	password: { type: String, required: true },
	password_reset_token: { type: String, default: null },
	reset_token_expired_at: { type: Date, default: null },
	role: { type: String, enum: ["Admin", "User"], default: "user" },
	active: { type: Boolean, default: true },
	created_at: { type: Date, default: Date.now },
	updated_at: { type: Date, default: Date.now },
});

module.exports = mongoose.model("User", userSchema);
