const mongoose = require('mongoose');

const MONGO_URI = process.env.URI || "mongodb://127.0.0.1:27017/test";

module.exports = {

    connect: async () => {
        await mongoose.connect(MONGO_URI, {
            useNewUrlParser: true
        });

        const db = mongoose.connection;

        db.on('error', () => {
            console.error.bind(console, 'MongoDB connection error');
            process.exit(1);
        });
        db.on('connection', console.log.bind(console, 'MongoDB connected'));

        return db;
    }
}