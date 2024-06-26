import express from 'express';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import hbs from 'nodemailer-express-handlebars';
import path from 'path';
import logger from '../helpers/logger.js';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const viewPath = path.resolve(__dirname, '../templates/views/');
const partialsPath = path.resolve(__dirname, '../templates/partials');

dotenv.config();

const mailSender = async (email, title, template, data = {}) => {
	try {
		// to send email ->  firstly create a Transporter
		const transporter = nodemailer.createTransport({
			host: process.env.MAIL_HOST, // -> Host SMTP detail
			auth: {
				user: process.env.MAIL_USERNAME, // -> User's mail for authentication
				pass: process.env.MAIL_PASSWORD, // -> User's password for authentication
			},
		});

		transporter.use(
			'compile',
			hbs({
				viewEngine: {
					extName: '.handlebars',
					layoutsDir: viewPath,
					defaultLayout: false,
					partialsDir: partialsPath,
					express,
				},
				viewPath,
				extName: '.handlebars',
			})
		);

		// now Send e-mails to users
		const staticData = {
			support_email: process.env.SUPPORT_EMAIL,
			current_year: new Date().getFullYear(),
			app_name: process.env.APP_NAME,
		};
		const info = await transporter.sendMail({
			from: process.env.MAIL_FROM_ADDRESS,
			to: `${email}`,
			subject: `${title}`,
			template: `${template}`,
			context: {
				...data,
				...staticData,
			},
		});
		return info;
	} catch (error) {
		logger.error(error.message);
	}
};

export default mailSender;
