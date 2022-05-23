const express = require('express');
const bcrypt = require('bcryptjs');
const router = express.Router();
const User = require('../model/user');
const jwtUtils = require('../config/JwtUtils');

router.post('/register', async (request, response, next) => {
    try {
        const user = new User({ ...request.body });

        const isUser = await User.findOne({ $or: [
            { username: user.username },
            { email: user.email }
        ]});

        if (isUser) {
            return response.status(409).send("User already exists!");
        }

        const encryptedPassword = await bcrypt.hash(user.password, 8);
        user.password = encryptedPassword;
        await user.save();

        return response.status(201).json(`User ${user.username} created successfully, please log in.`);
    } catch (err) {
        return next(err);
    }
});

router.post('/login', async (request, response, next) => {
    try {
        const { username, password } = request.body;

        if (!(username) || !(password)) {
            return response.status(400).send("Incomplete login fields.");
        }

        const user = await User.findOne({ username }).select('+password');

        if (user) {
            if (await bcrypt.compare(password, user.password)) {
                const token = jwtUtils.generateAccessToken(user.username);
                response.setHeader('Authorization', token);
                user.password = undefined;

                return response.status(200).json(user);
            }
        }
        return response.status(400).send("Invalid login details.");

    } catch (err) {
        return next(err);
    }
});

module.exports = router;