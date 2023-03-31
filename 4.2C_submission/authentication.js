//importing the required packages
const passport = require('passport');
const passportJWT = require('passport-jwt');
const JWTStrategy   = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;
const jwt = require('jsonwebtoken');

// Setting the secret key
const secret = 'mySecretKey';

//Passport.js uses JWT for authentication here through the Bearer token
passport.use(new JWTStrategy({
        jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
        secretOrKey   : secret
    },
    function (jwtPayload, done) {
        // Checks if the JWT token is valid i.e., not expired. Returns the user data if token is valid
        if (Date.now() > jwtPayload.expires) {
            return done('jwt expired', false);
        }
        return done(null, jwtPayload.user);
    }
));

// Generate a new JWT token
function generateToken(user) {
    const payload = { user };
    const token = jwt.sign(payload, secret, { expiresIn: '1h' });
    return token;
}

module.exports = { passport, generateToken };
