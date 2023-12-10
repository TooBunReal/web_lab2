const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = "mongodb+srv://TooBunReal:Mk0378203515@dbcluster.orpnbw1.mongodb.net/?retryWrites=true&w=majority";
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,

    }
});

const dbName = "DB_Lab";
const collectionName = "User_Lab";
const database = client.db(dbName);
const collection = database.collection(collectionName);
const crypto = require('crypto');

function hashPassword(password) {
    const sha256 = crypto.createHash('sha256');
    sha256.update(password);
    return sha256.digest('hex');
}

function isValidEmail(email) {
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!regex.test(email)) {
        console.log('Invalid email');
        return false;
    }
    return true;
}

function isValid(password) {
    const uppercaseRegex = /[A-Z]/;
    const lowercaseRegex = /[a-z]/;
    const digitRegex = /\d/;
    const specialCharRegex = /[!@#$%^&*()]/;
    if (!uppercaseRegex.test(password) || !lowercaseRegex.test(password) || !digitRegex.test(password) || !specialCharRegex.test(password)) {
        console.log('Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character');
        return false;
    }
    return true;
}

async function register(_email, _username, _name, _password, _phonenumber,) {
    if (!isValidEmail(_email)) {
        console.log('Invalid email');
        return false;
    }
    if (!isValid(_password)) {
        console.log('Invalid password');
        return false;
    }
    var query = { username: _username };
    try {
        var queryResult = await collection.find(query).toArray();
        if (queryResult.length > 0) {
            console.log("User already exists");
            return false;
        } else {
            const recipes = [
                {
                    username: _username,
                    password: hashPassword(_password),
                    email: _email,
                    name: _name,
                    phonenumber: _phonenumber
                },
            ];

            try {
                const insertManyResult = await collection.insertMany(recipes);
                console.log(`${insertManyResult.insertedCount} Register successful.\n`);
                return true;
            } catch (err) {
                console.log(`Register failed: ${err}\n`);
                return false;
            }
        }
    } catch (err) {
        console.log(`Register failed: ${err}\n`);
    }
}


async function login(_email, _password) {
    var query = { email: _email, password: hashPassword(_password) };
    try {
        var queryResult = await collection.find(query).toArray();
        if (queryResult.length > 0) {
            console.log("Login successful");
            return true;
        } else {
            console.log("Login fail");
            return false;
        }
    } catch (err) {
        console.error(`Login fail: ${err}\n`);
    }
}

module.exports = { register, login };