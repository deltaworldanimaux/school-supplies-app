// models/DeliveryDriver.js
const mongoose = require('mongoose');

const deliveryDriverSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  phone: {
    type: String,
    required: true,
    unique: true
  },
  score: {
    type: Number,
    default: 0
  },
  isActive: {
    type: Boolean,
    default: true
  },
  currentOrder: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Order',
    default: null
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('DeliveryDriver', deliveryDriverSchema);