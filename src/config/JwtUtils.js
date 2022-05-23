// require('crypto').randomBytes(64).toString('hex') // use to generate random 64 byte string for the token secret
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

dotenv.config();

const SECRET = process.env.TOKEN_SECRET;

/** 
* Returns a signed Json Web Token (JWT) token for the given unique identifier, a username in an object. This token will be valid for
* up to 24 hours. 
*
* @param {object} username - A username to be hashed in the token.
* @return {string} A base64 string representing the signed JWT.
*/
function generateAccessToken(username) {
    return jwt.sign({ username }, SECRET, { expiresIn: "1d" })
}

/**
 * Add this function to the Express middleware stack, or to the middleware stack of a route, to apply
 * JWT authentication middleware.
 */
function authenticationMiddleware(request, response, next) {
    const authHeader = request.header('authorization');
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return response.status(401).send('A token is required for authentication.');
    }
    
    jwt.verify(token, SECRET, (error, user) => {
        if (error) {
            console.error(error);
            return response.status(403).send('Invalid token supplied.');
        }
        request.user = user;
        next();
    });
}


module.exports = {
    generateAccessToken,
    authenticationMiddleware
}