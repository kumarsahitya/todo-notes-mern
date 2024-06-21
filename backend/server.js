import express from 'express';
import dotenv from 'dotenv'
import mongodb from './src/configs/mongodb.js';
const app = express();
import morganMiddleware from './src/middlewares/morganMiddleware.js';

// The morgan middleware does not need this.
// This is for a manual log
import logger from './src/helpers/logger.js';

dotenv.config();
const PORT = process.env.PORT || 4000;

// json
app.use(express.json());

// cors
app.use((req, res, next) => {
	res.setHeader('Access-Control-Allow-Origin', '*');
	res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
	res.setHeader(
		'Access-Control-Allow-Headers',
		'Content-Type, Authorization',
	);
	next();
});
app.use(morganMiddleware);

// calling database connection function
mongodb.connect();

// route importing and mounting
import user from './src/routes/user.js';

// test api
app.get('/test', (req, res) => {
	try {
		res.status(200).json({ message: 'API is working' });
	} catch (error) {
		res.status(500).json({ message: error.message });
	}
});

app.listen(PORT, () => {
	logger.info('Server Started');
});
