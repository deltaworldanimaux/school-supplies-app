// models/DeliveryMan.js
const mongoose = require('mongoose');

const deliveryManSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  phone: {
    type: String,
    required: true,
    unique: true
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
  score: {
    type: Number,
    default: 0
  },
  isAvailable: {
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

module.exports = mongoose.model('DeliveryMan', deliveryManSchema);