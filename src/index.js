require('dotenv').config();
const express = require('express');
const database = require('./config/database.config');
const authenticationRouter = require('./route/AuthenticationRouter');
const exampleRouter = require('./route/ExampleRouter');

const PORT = process.env.PORT || 3000;

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(authenticationRouter);
app.use('/example', exampleRouter);

async function main() {
    await database.connect();

    app.listen(PORT, () => {
        console.log(`Server up on ${PORT}`);
    });
}

main();