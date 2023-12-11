const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();
const secretKey = process.env.SECRET_KEY;

function authToken(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect('/login');
    }

    try {
        jwt.verify(token, secretKey);
        next();
    } catch (error) {
        return res.redirect('/login');
    }
}

module.exports = {
    authToken
};