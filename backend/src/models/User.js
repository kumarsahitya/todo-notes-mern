const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const UserSchema = new mongoose.Schema({
	first_name: { type: String, required: true, default: '', trim: true },
	last_name: { type: String, required: true, default: '', trim: true },
	email: { type: String, unique: true, required: true, index: true },
	phone: { type: String, default: '' },
	avatar: { type: String, default: '' },
	avatar_last_updated: { type: Date, default: null },
	password: { type: String, required: true },
	reset_token_expired_at: { type: Date, default: null },
	role: { type: String, enum: ['Admin', 'User'], default: 'User' },
	active: { type: Boolean, default: true },
	created_at: { type: Date, default: Date.now },
	updated_at: { type: Date, default: Date.now },
	deleted_at: { type: Date, default: null },
	user_attribute_id: { type: mongoose.Schema.ObjectId, ref: 'UserAttribute' },
});

UserSchema.pre('save', function (next) {
	const user = this;

	if (user.isModified('password') === false) {
		next();
	}

	bcrypt.genSalt(Number(process.env.BCRYPT_SALT), (err, salt) => {
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
