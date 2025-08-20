const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  parentName: {
    type: String,
    required: true
  },
  phone: {
    type: String,
    required: true
  },
  studentName: {
    type: String,
    required: true
  },
  grade: {
    type: String,
    required: true
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
  suppliesList: {
    type: String, // This will store the filename
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'processing', 'delivered'],
    default: 'pending'
  }
}, {
  timestamps: true
});

orderSchema.index({ location: '2dsphere' });

module.exports = mongoose.model('Order', orderSchema);