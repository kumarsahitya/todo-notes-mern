import { Tag } from '../models/Tag.js';
import { body, param } from 'express-validator';
import { ObjectId } from 'mongodb';

const addRules = [
	body('name')
		.exists({ checkFalsy: true })
		.withMessage('Name is required')
		.isString()
		.withMessage('Name should be string')
		.custom(async (value) => {
			const tag = await Tag.findOne({ name: value });
			if (tag) {
				throw new Error('A tag already exists with this name');
			}
		}),
	param('parent_id')
		.customSanitizer((value) => ObjectId.createFromHexString(value))
		.custom(async (value) => {
			const tag = await Tag.findById(ObjectId.createFromHexString(value));
			if (!tag) {
				throw new Error('Invalid tag id');
			}
		}),
];

export default {
	addRules,
};
