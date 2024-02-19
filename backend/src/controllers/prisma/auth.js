const bcrypt = require('bcrypt');
const { prisma } = require('../configs/prisma');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { sendVerificationEmail } = require('./traits/user');
require('dotenv').config();

// signup handle
exports.signup = async (req, res) => {
    try {
        // get input data
        const { first_name, last_name, email, password, phone } = req.body;

        // Check if All Details are there or not
        if (!first_name || !last_name || !email || !password) {
            return res.status(403).send({
                success: false,
                message: 'All Fields are required',
            });
        }

        // check if use already exists?
        // Using prisma
        const existingUser = await prisma.users.findUnique({
            where: { email },
        });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User already exists',
            });
        }

        // secure password
        let hashedPassword;
        try {
            hashedPassword = await bcrypt.hash(password, 10);
        } catch (error) {
            return res.status(500).json({
                success: false,
                message:
                    `Hashing pasword error for ${password}: ` + error.message,
            });
        }

        // sending email for verification
        const emailToken = await crypto.randomBytes(16).toString('hex');
        const userData = {
            first_name,
            last_name,
            email,
            password: hashedPassword,
            phone,
            email_verify_token: emailToken,
            role: 'User',
        };

        // Using prisma
        const userInstance = await prisma.users.create({ data: userData });

        userInstance.password = undefined;
        try {
            if (await sendVerificationEmail(req, userInstance)) {
                return res.status(200).json({
                    success: true,
                    message: `A verification email has been sent to ${userInstance.email}.`,
                    data: { user: userInstance },
                });
            }
        } catch (error) {
            return res.status(500).json({
                success: false,
                message: `Error occurred while sending email: ${error.message}`,
            });
        }

        return res.status(200).json({
            success: true,
            message: 'user created successfully.',
            data: { user: userInstance },
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            success: false,
            message: 'User registration failed',
        });
    }
};

exports.login = async (req, res) => {
    try {
        // data fetch
        const { email, password } = req.body;
        // validation on email and password
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Plz fill all the details carefully',
            });
        }

        // check for registered User
        // Using prisma
        const userInstance = await prisma.users.findUnique({
            where: { email },
        });

        // if user not registered or not found in database
        if (!userInstance) {
            return res.status(401).json({
                success: false,
                message: 'You have to Signup First',
            });
        }

        // validate user is active and verified email
        if (!userInstance.active) {
            return res.status(401).json({
                success: false,
                message:
                    'You account has been inactive. Please contact admin or verify email address first',
            });
        }
        if (!userInstance.email_verified) {
            try {
                const emailToken = await crypto.randomBytes(16).toString('hex');
                userInstance.email_verify_token = emailToken;
                if (await userInstance.save()) {
                    await sendVerificationEmail(req, userInstance);
                }
            } catch (error) {}
            return res.status(401).json({
                success: false,
                message:
                    'Unable to login into your account. Please verify email address first',
            });
        }

        const payload = {
            email: userInstance.email,
            id: userInstance._id,
            role: userInstance.role,
        };
        // verify password and generate a JWt token 🔎
        if (await bcrypt.compare(password, userInstance.password)) {
            // if password matched
            // now lets create a JWT token
            const token = jwt.sign(payload, process.env.JWT_SECRET, {
                expiresIn: process.env.JWT_EXPIRES_IN,
            });
            // userInstance = userInstance.toObject();
            // userInstance.token = token;

            userInstance.password = undefined;
            const options = {
                expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
                httpOnly: true, // It will make cookie not accessible on clinet side -> good way to keep hackers away
            };
            res.cookie('token', token, options)
                .status(200)
                .json({
                    success: true,
                    message: 'Logged in Successfully.',
                    data: { token, user: userInstance },
                });
        } else {
            // password donot matched
            return res.status(403).json({
                success: false,
                message: 'Password incorrects!',
            });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({
            success: false,
            message: `Login failure: ${error.message}`,
        });
    }
};

// It is GET method, you have to write like that
exports.confirmation = async (req, res) => {
    try {
        // data fetch
        const { email, token } = req.params;
        // validation on email and password
        if (!email || !token) {
            return res.status(400).json({
                success: false,
                message: 'In valid request parameters',
            });
        }

        // check for registered User
        // Using prisma
        const userInstance = await prisma.users.findUnique({
            where: { email, email_verify_token: token },
        });

        // if user not registered or not found in database
        if (!userInstance) {
            return res.status(401).json({
                success: false,
                message: 'You have to Signup First',
            });
        }
        // user is already verified
        else if (userInstance.email_verified) {
            return res.status(200).json({
                success: true,
                message: 'Your email has been already verified. Please Login',
            });
        } else {
            // change isVerified to true and mark active
            // Using prisma
            const updateUser = await prisma.users.update({
                where: {
                    id: userInstance.id,
                },
                data: {
                    active: true,
                    email_verified: true,
                    email_verify_token: null,
                },
            });
            if (updateUser) {
                return res.status(200).json({
                    success: true,
                    message: 'Your account has been successfully verified',
                });
            } else {
                return res.status(500).json({
                    success: false,
                    message: 'Unable to verify your email address',
                });
            }
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({
            success: false,
            message: `Email Verification failed: ${error.message}`,
        });
    }
};
