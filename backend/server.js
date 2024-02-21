const express = require('express');
const app = express();
const logger = require('./src/helpers/logger');

require('dotenv').config();
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

// calling database connection function
require('./src/configs/mongodb').connect();

// route importing and mounting
const user = require('./src/routes/user');
app.use('/api/v1/auth', user);

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
