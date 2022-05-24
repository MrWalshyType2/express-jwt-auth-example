require('dotenv').config();
const express = require('express');
const database = require('./config/database.config');
const authenticationRouter = require('./route/AuthenticationRouter');
const exampleRouter = require('./route/ExampleRouter');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const PORT = process.env.PORT || 5500;

const app = express();

app.use(cors({
    origin: ['http://127.0.0.1:3000', 'http://127.0.0.1:5500'],
    credentials: true // include cookies on cross-origin requests
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());

app.use(authenticationRouter);
app.use('/example', exampleRouter);

/** 
* This is the entry point to the API, this will start the database and the server when called.
*/
async function main() {
    await database.connect();

    app.listen(PORT, () => {
        console.log(`Server up on ${PORT}`);
    });
}

main();