const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const {logger} = require("./logger.js");
const {config} = require("./config");
const {auth} = require("express-oauth2-jwt-bearer");
const {checkIfBlocked} = require('./utils/history');
const {saveUnsuccessfulAttempt} = require('./utils/history');
const {registerUser} = require('./utils/user');
const {getUserDetailedInformation} = require('./utils/user');
const {refreshAccessToken} = require('./utils/auth');
const {authUserByLoginAndPassword} = require('./utils/auth');
const {getAccessToken} = require('./utils/auth');
const {verifyToken} = require('./utils/token-validation');
const {getUserAccessTokenByCode} = require('./utils/sso-login');

const uuid = require("uuid");
const cookieParser = require("cookie-parser");

const userInfo = {}

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(cookieParser());

function retrieveToken(request) {
    const headerValue = request.get(config.sessionKey);
    if (headerValue) {
        token = headerValue.split(" ")[1];
        if (token) {
            return token;
        }
    }
    return null;
}

const checkJwt = auth({
    audience: config.audience,
    issuerBaseURL: `https://${config.domain}`,
});

app.use(async (req, res, next) => {
    let token = retrieveToken(req);
    if (token) {
        const payload = await verifyToken(token);
        if (payload) {
            const userId = payload.sub;
            const tokenValidTime = userInfo[payload.sub].expiresIn - 4 * 60 * 60 * 1000;
            if (Date.now() >= tokenValidTime) {
                token = await refreshAccessToken(userId, userInfo);
            }
            req.token = token
            req.userId = userId;
        }
    }
    next();
});

app.get('/userinfo', checkJwt, function (req, res) {
    const {token} = req;
    if (token) {
        const message = `User details:\n   name: ${userInfo[req.userId].name}\n    email: ${userInfo[req.userId].email}`;
        res.json({
            token: token,
            message: message
        });
    }
});

app.get('/', async (req, res) => {
    const queryParams = req.query;
    if (queryParams.code) {
        try {
            const {code} = queryParams;
            const authInfo = await getUserAccessTokenByCode(code);
            res.setHeader('accesstoken', authInfo.accessToken);
            const payload = await verifyToken(authInfo.accessToken);
            if (payload != null) {
                const userId = payload.sub;
                const ip = req.socket.remoteAddress;
                logger.info(`Successfully logged in, IP: ${ip}, user: ${userId}`);
                const userDetailedInfo = await getUserDetailedInformation(userId, authInfo.accessToken);
                userDetailedInfo.refreshToken = authInfo.refreshToken;
                userDetailedInfo.accessToken = authInfo.accessToken;
                userDetailedInfo.expiresIn = Date.now() + authInfo.expiresIn * 1000;
                userInfo[userId] = userDetailedInfo;
            }
        } catch {}
    } else {
        const {token} = req;
        if (token) {
            const {userId} = req;
            return res.json({
                token: token,
                username: userInfo[userId].name
            });
        }
    }
    return res.sendFile(path.join(__dirname + '/index.html'));
});

app.get('/logout', (req, res) => {
    res.redirect(`https://${config.domain}/v2/logout?client_id=${config.clientId}&returnTo=http://localhost:3000/`);
});

app.post('/logout', async (req, res) => {
    try {
        const userId = req.userId;
        if (!userId) {
            return res.status(401).send();
        }
        console.log(`User with id ${userId} successfully logout`);
        delete userInfo[req.userId];
    } catch (err) {
        console.error(err);
        res.status(500).send();
    }
});

app.post('/api/login', async (req, res) => {
    const {login, password} = req.body;
    const authInfo = await authUserByLoginAndPassword(login, password);
    const ip = req.socket.remoteAddress;
    if (authInfo.accessToken !== undefined && !checkIfBlocked(ip)) {
        logger.info(`Successfully logged in, IP: ${ip}, user: ${login}`);
        const payload = await verifyToken(authInfo.accessToken);
        const userId = payload.sub;
        const userDetailedInfo = await getUserDetailedInformation(userId, authInfo.accessToken);
        userDetailedInfo.refreshToken = authInfo.refreshToken;
        userDetailedInfo.accessToken = authInfo.accessToken;
        userDetailedInfo.expiresIn = Date.now() + authInfo.expiresIn * 1000;
        userInfo[userId] = userDetailedInfo;
        return res.json({
            token: authInfo.accessToken
        });
    } else {
        saveUnsuccessfulAttempt(ip);
        logger.info(`Unsuccessful attempt to login from IP: ${ip}`);
    }
    return res.status(401).send();
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname + '/signup.html'));
});

app.post('/api/signup', async (req, res) => {
    const {login, password, name, nickname} = req.body;
    const clientAccessToken = await getAccessToken();
    const result = await registerUser(clientAccessToken, login, password, name, nickname);
    if (result) {
        logger.info(`Successfully registered user with login ${login}`);
        return res.json({redirect: '/'});
    }
    return res.status(500).send();
});

app.get('/login', async (req, res) => {
    const state_id = uuid.v4();
    res.redirect(`https://${config.domain}/authorize?response_type=code&client_id=${config.clientId}&redirect_uri=http://localhost:3000&scope=offline_access read:users read:current_user read:user_idp_tokens&audience=${config.audience}&state=${config.state}${state_id}`);
});

app.listen(config.port, () => {
    logger.info(`Example app listening on port ${config.port}`);
});
