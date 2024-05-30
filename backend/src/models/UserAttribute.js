const mongoose = require('mongoose');

const UserAttributeSchema = new mongoose.Schema({
	user_id: { type: mongoose.Schema.ObjectId, ref: 'User' },
	default_location_name: { type: String, default: '', trim: true },
	default_latitude: { type: mongoose.Decimal128, default: null },
	default_longitude: { type: mongoose.Decimal128, default: null },
	comments: { type: String, default: null },
	email_verified: { type: Boolean, default: false },
	email_verify_token: { type: String, default: null },
	email_last_verified: { type: Date, default: null },
	date_agreed_to_terms_of_service: { type: Date, default: null },
	password_updated: { type: Date, default: null },
	last_login_at: { type: Date, default: null },
});

module.exports = mongoose.model('UserAttribute', UserAttributeSchema);
