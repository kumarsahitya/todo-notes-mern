import mongoose from 'mongoose';

const TagSchema = new mongoose.Schema({
	name: { type: String, required: true, default: '', trim: true },
	parent_id: { type: mongoose.Schema.ObjectId, ref: 'Tag' },
	created_at: { type: Date, default: Date.now },
	updated_at: { type: Date, default: Date.now },
	deleted_at: { type: Date, default: null },
});

const Tag = mongoose.model('Tag', TagSchema);

export default Tag;
