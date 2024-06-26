import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';

// Define your severity levels.
// With them, You can create log files,
// see or hide levels based on the running ENV.
const levels = {
	error: 0,
	warn: 1,
	info: 2,
	http: 3,
	debug: 4,
};

// This method set the current severity based on
// the current NODE_ENV: show all the log levels
// if the server was run in development mode; otherwise,
// if it was run in production, show only warn and error messages.
const level = () => {
	const env = process.env.NODE_ENV || 'development';
	const isDevelopment = env === 'development';
	return isDevelopment ? 'debug' : 'warn';
};

// Define different colors for each level.
// Colors make the log message more visible,
// adding the ability to focus or ignore messages.
const colors = {
	error: 'red',
	warn: 'yellow',
	info: 'green',
	http: 'magenta',
	debug: 'white',
};

// Tell winston that you want to link the colors
// defined above to the severity levels.
winston.addColors(colors);

const logger = winston.createLogger({
	level: level(),
	levels,
	format: winston.format.combine(
		// Add the message timestamp with the preferred format
		winston.format.timestamp(),
		// Define the format of the message showing the timestamp, the level and the message
		winston.format.printf(
			(info) => `[${info.timestamp}] ${info.level}: ${info.message}`,
		),
	),

	// Define which transports the logger must use to print out messages.
	// In this example, we are using three different transports
	transports: [
		// Allow the use the console to print the messages
		new winston.transports.Console({
			format: winston.format.colorize({ all: true }),
		}),
		// Allow to print all the error level messages inside the application-daily.log file
		new DailyRotateFile({
			filename: 'logs/application-%DATE%.log',
			datePattern: 'YYYY-MM-DD',
			zippedArchive: true,
			maxSize: '20m',
			maxFiles: '14d',
		}),
	],
});

export default logger;
