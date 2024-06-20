import mongoose from 'mongoose';

const NoteAttributeSchema = new mongoose.Schema({
	user_id: { type: mongoose.Schema.ObjectId, ref: 'User' },
	note_id: { type: mongoose.Schema.ObjectId, ref: 'Note' },
	subject_date: { type: Date, default: Date.now },
	latitude: { type: mongoose.Decimal128, default: null },
	longitude: { type: mongoose.Decimal128, default: null },
	altitude: { type: mongoose.Decimal128, default: null },
	reminder_order: { type: Number, default: 1 },
	reminder_done_time: { type: Date, default: null },
	reminder_ime: { type: Date, default: null },
	place_name: { type: String, default: '' },
	last_editor_id: { type: mongoose.Schema.ObjectId, ref: 'User' },
});

export default mongoose.model('NoteAttribute', NoteAttributeSchema);
