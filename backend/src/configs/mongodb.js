const mongoose = require('mongoose');
const logger = require('../helpers/logger');

require('dotenv').config();
module.exports = {
	/**
	 * Connects to the MongoDB database using the provided MongoDB URL.
	 *
	 * @return {Promise} A promise that resolves when the connection is successful and rejects with an error if the connection fails.
	 */
	connect: () => {
		mongoose
			.connect(process.env.MONGODB_URL)
			.then(() => logger.info('DB Connected Successfully.'))
			.catch((error) => {
				logger.error('this error occured' + error);
				process.exit(1);
			});
	},
};
