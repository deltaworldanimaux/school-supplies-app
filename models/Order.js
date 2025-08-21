// models/Order.js
const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  parentName: { type: String, required: true },
  phone: { type: String, required: true },
  studentName: { type: String, required: true },
  grade: { type: String, required: true },
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
  suppliesList: { type: String, required: true },
  status: { type: String, default: 'pending' },
  orderNumber: { type: String, required: true, unique: true },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Library' } // Fixed the colon here
}, {
  timestamps: true
});

orderSchema.index({ location: '2dsphere' });

module.exports = mongoose.model('Order', orderSchema);