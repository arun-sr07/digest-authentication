const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const asyncHandler = require('express-async-handler');

const authMiddleware = asyncHandler(async (req, res, next) => {
    let token;

    if (req?.headers?.authorization?.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];

        try {
            if (token) {
                const decoded = jwt.verify(token, process.env.JWT_SECRET);
                // Set the user in the request object
                req.user = decoded;
                next();
            }
        } catch (error) {
            console.error('Authentication error:', error);
            return res.status(401).json({ message: 'Unauthorized' });
        }
    } else {
        return res.status(401).json({ message: 'No token attached to header' });
    }
});

const isAdmin = asyncHandler(async (req, res, next) => {
    const { email } = req.user;

    try {
        console.log('Email:', email);

        const adminUser = await User.findOne({ email });

        if (!adminUser) {
            throw new Error('User not found');
        }

        console.log('User Role:', adminUser.role);

        if (adminUser.role !== 'admin') {
            throw new Error('You are not an admin');
        }

        next();
    } catch (error) {
        console.error('isAdmin middleware error:', error);
        return res.status(403).json({ message: 'Forbidden' });
    }
});



module.exports = { authMiddleware, isAdmin };
