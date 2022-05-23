const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');

const userSchema = new Schema({
    username: {
        type: String,
        default: null,
        required: [true, 'Usernames are required and must be at least 4 characters in length, but no more than 32'],
        minlength: 4,
        maxlength: 32,
        trim: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6,
        select: false // prevent password from being returned in every request from db
    },
    email: {
        type: String,
        minlength: 8,
        maxlength: 128,
        trim: true,
        required: [true, 'Email must be at least 8 characters and no more than 128'],
        unique: true,
        match: /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
    },
    createdAt: {
        type: Date,
        default: Date.now()
    },
    role: {
        type: String,
        enum: ['ADMIN', 'MEMBER'],
        default: 'MEMBER'
    }
});

// document middleware, hooking into the middleware for save operations on documents
userSchema.pre('save', async function(next) {
    // hash+salt the currently set password if it is new or has been modified
    if (this.password && this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 8);
    }

    // must be called to advance Mongooses middleware chain
    next();
});

const User = mongoose.model('User', userSchema);

module.exports = User;