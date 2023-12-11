const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;

dotenv.config();

const { register, login } = require("./db/dataquerry.js");
const { authToken } = require('./middleware/middleware.js');


const app = express();
const port = 8080;
const secretKey = process.env.SECRET_KEY;

app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false
}));


passport.use(new GoogleStrategy({
    clientID: "968813383697-cvsbkkscaa26rfm4q3i0s8qjmqin3gnu.apps.googleusercontent.com",
    clientSecret: "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",
    callbackURL: "http://localhost:8080/auth/google/callback"
}, (accessToken, refreshToken, email, profile, done) => {
    done(null, email);
}));

passport.use(
    new FacebookStrategy(
        {
            clientID: '1099187007928932',
            clientSecret: '58104d4fe1dc529b7adf801f2443cea5',
            callbackURL: 'http://localhost:8080/auth/facebook/callback',
            profileFields: ['id', 'displayName', 'email'],
        },
        (accessToken, refreshToken, profile, done) => {
            done(null, profile);
        }
    )
);

app.use(express.static(path.join(__dirname, '../public')));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(passport.initialize());
app.use(passport.session());



app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../public', 'templates', 'main.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '../public', 'templates', 'register.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '../public', 'templates', 'login.html'));
});

app.get('/store', authToken, (req, res) => {
    res.sendFile(path.join(__dirname, '../public', 'templates', 'store.html'));
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'], session: false }));

app.get('/auth/google/callback', (req, res, next) => {
    passport.authenticate('google', (err, profile) => {
        req.user = profile
        next()
    })(req, res, next)
}, (req, res) => {
    const id = req.user.id_token;
    const decodedToken = jwt.decode(id);
    const token = jwt.sign({ email: decodedToken.email }, secretKey);
    res.cookie('token', token, { maxAge: 3600000 });
    res.redirect('/store')
})

app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

app.get('/auth/facebook/callback', (req, res, next) => {
    passport.authenticate('facebook', (err, profile) => {
        req.user = profile
        next()
    })(req, res, next)
}, (req, res) => {
    const email = req.user.emails[0].value;
    const token = jwt.sign({ email: email }, secretKey);
    res.cookie('token', token, { maxAge: 3600000 });
    res.redirect('/store')
})

app.post('/register', (req, res) => {
    if (req.body.password != req.body.confirm_password) {
        console.log("pass not match");
        return res.redirect('/register');
    }
    register(req.body.email, req.body.username, req.body.name, req.body.password, req.body.phonenumber)
        .then((result) => {
            if (result === true) {
                return res.redirect('/login');
            } else {
                console.log("Register fail");
                return res.redirect('/register');
            }
        })
        .catch((error) => {
            console.error(error);
            return res.redirect('/register');
        });
});

app.post("/login", function (req, res) {
    login(req.body.email, req.body.password)
        .then((result) => {
            if (result === true) {
                const token = jwt.sign({ email: req.body.email }, secretKey);
                res.cookie('token', token, { maxAge: 3600000 }); //millisecond
                res.redirect('/store');
            } else {
                console.log("sai");
                return res.redirect('/login');
            }
        })
        .catch((error) => {
            console.error(error);
            return res.redirect('/login');
        });
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});