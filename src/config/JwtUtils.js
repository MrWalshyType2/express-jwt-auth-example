// require('crypto').randomBytes(64).toString('hex') // use to generate random 64 byte string for the token secret
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

dotenv.config();

const SECRET = process.env.TOKEN_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;
const JWT_TIMEOUT = (60 * 30); // 60 seconds * 30
const MS_PER_MINUTE = 3600;

/** 
* Returns a signed Json Web Token (JWT) token for the given unique identifier, a username in an object. This token will be valid for
* up to 30 minutes. 
*
* @param {object} username - A username to be hashed in the token.
* @return {string} A base64 string representing the signed JWT.
*/
function generateAccessToken(username, role) {
    return jwt.sign({ username, role }, SECRET, { expiresIn: JWT_TIMEOUT });
}

function generateRefreshToken(username, role) {
    return jwt.sign({ username, role }, REFRESH_SECRET, { expiresIn: "1d" });
}

function refreshAccessTokenMiddleware(request, response, next) {
    // console.log(request.cookies);
    const refreshToken = request.cookies.refreshToken;

    if (refreshToken) {
        jwt.verify(refreshToken, REFRESH_SECRET, (error, token) => {
            if (error) {
                return response.status(403).send('Invalid refresh token supplied.');
            }
            const user = request.user;
            const newToken = generateAccessToken(user.username, user.role);
            
            return response.status(200).json({ newToken, expiration: JWT_TIMEOUT, user });
        });
    } else {
        return response.status(400).send('No refresh token supplied.');
    }
}

/**
 * Add this function to the Express middleware stack, or to the middleware stack of a route, to apply
 * JWT authentication middleware.
 */
function authenticationMiddleware(request, response, next) {
    const authHeader = request.header('authorization');
    // tokens are sent in the form: Authorization: Bearer jr9480rhj48787yth84yh387thy48t7yh4
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return response.status(401).send('A token is required for authentication.');
    }
    
    // the SECRET is used to verify that the token has NOT changed
    // - user is extracted from the JWT
    jwt.verify(token, SECRET, (error, user) => {
        if (error) {
            console.error(error);
            return response.status(403).send('Invalid token supplied.');
        }
        // attach the user to the request object
        request.user = user;
        console.log(`User ${user.username} was authorized successfully.`);

        // pass control to the next piece of middleware
        next();
    });
}

/**
 * This middleware checks if the user is an admin, this should be called after authenticationMiddleware
 * in the middleware chain.
 * @param {*} request 
 * @param {*} response 
 * @param {*} next 
 * @returns 
 */
function isAdmin(request, response, next) {
    if (request.user.role === 'ADMIN') {
        console.log(`Admin access granted to: ${request.user.username}`);
        return next();
    }
    console.log(`Admin access denied to: ${request.user.username}`);
    return response.status(403).send('Invalid token supplied.');
}


module.exports = {
    generateAccessToken,
    generateRefreshToken,
    authenticationMiddleware,
    refreshAccessTokenMiddleware,
    isAdmin,
    JWT_TIMEOUT
}