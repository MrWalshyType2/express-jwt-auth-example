require('dotenv').config();
const express = require('express');
const database = require('./config/database.config');
const authenticationRouter = require('./route/AuthenticationRouter');
const exampleRouter = require('./route/ExampleRouter');
const cors = require('cors');

const PORT = process.env.PORT || 5500;

const app = express();

app.use(cors("*"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

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