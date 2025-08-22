// models/Library.js
const mongoose = require('mongoose');

const librarySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  location: {
    type: {
      type: String,
      enum: ['Point'],
      required: true
    },
    coordinates: {
      type: [Number],
      required: true
    }
  },
  phone: {
    type: String,
    required: true
  },
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  plainPassword: {
    type: String,
    required: true
  },
  // Add this new field
  telegramChatId: {
    type: String,
    default: null
  }
}, {
  timestamps: true
});

librarySchema.index({ location: '2dsphere' });

module.exports = mongoose.model('Library', librarySchema);