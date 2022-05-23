const express = require('express');
const router = express.Router();
const { authenticationMiddleware } = require('../config/JwtUtils');

router.get('/', (request, response) => {
    response.send("For all to see");
});

router.get('/members', authenticationMiddleware, (request, response) => {
    response.send("Members only here");
});

module.exports = router;