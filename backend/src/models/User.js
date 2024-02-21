const SALT_WORK_FACTOR = 10;
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const UserSchema = new mongoose.Schema({
	first_name: { type: String, required: true, default: '', trim: true },
	last_name: { type: String, required: true, default: '', trim: true },
	email: { type: String, unique: true, required: true, index: true },
	email_verified: { type: Boolean, default: false },
	email_verify_token: { type: String, default: null },
	phone: { type: String, default: '' },
	avatar: { type: String, default: '' },
	password: { type: String, required: true },
	password_reset_token: { type: String, default: null },
	reset_token_expired_at: { type: Date, default: null },
	role: { type: String, enum: ['Admin', 'User'], default: 'User' },
	active: { type: Boolean, default: true },
	created_at: { type: Date, default: Date.now },
	updated_at: { type: Date, default: Date.now },
});

UserSchema.pre('save', function (next) {
	const user = this;

	if (user.isModified('password') === false) {
		next();
	}

	bcrypt.genSalt(SALT_WORK_FACTOR, (err, salt) => {
		if (err) {
			return next(err);
		}

		// the new salt hashes the new password
		bcrypt.hash(user.password, salt, (error, hash) => {
			if (error) {
				return next(error);
			}

			// the clear text password overidden
			user.password = hash;
			return next();
		});
	});
});

module.exports = mongoose.model('User', UserSchema);
