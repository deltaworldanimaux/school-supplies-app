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
  status: { 
  type: String, 
  default: 'pending',
  enum: ['pending', 'confirmed', 'processing', 'ready', 'delivered']
},
  orderNumber: { type: String, required: true, unique: true },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Library' },
  cost: { type: Number, default: null },
  refusalReason: { type: String, default: null }, // Add refusal reason field
  deliveryMan: { type: mongoose.Schema.Types.ObjectId, ref: 'DeliveryMan' },
deliveryStatus: { 
  type: String, 
  default: 'pending',
  enum: ['pending', 'assigned', 'picked_up', 'delivered']
},
deliveryCost: { type: Number, default: null },
city: { type: String, default: null },
rejectedBy: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'DeliveryMan'
  }]
}, {
  timestamps: true
});

orderSchema.index({ location: '2dsphere' });

module.exports = mongoose.model('Order', orderSchema);