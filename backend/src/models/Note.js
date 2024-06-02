const mongoose = require('mongoose');

const NoteSchema = new mongoose.Schema({
	title: { type: String, required: true, default: '', trim: true },
	content: { type: String, required: true, default: '', trim: true },
	active: { type: Boolean, default: true },
	created_at: { type: Date, default: Date.now },
	updated_at: { type: Date, default: Date.now },
	deleted_at: { type: Date, default: null },
	tag_ids: [{ type: mongoose.Schema.ObjectId, ref: 'Tag' }],
	note_attribute_id: { type: mongoose.Schema.ObjectId, ref: 'NoteAttribute' },
});

module.exports = mongoose.model('Note', NoteSchema);
