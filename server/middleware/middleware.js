const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

const secretKey = process.env.SECRET_KEY;

function authToken(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect('/login');
    }
    next();
}
module.exports = {
    authToken
};