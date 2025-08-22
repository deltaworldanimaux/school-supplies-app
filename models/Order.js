// models/Order.js (updated)
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
    enum: ['pending', 'confirmed', 'processing', 'ready', 'delivered', 'out_for_delivery']
  },
  orderNumber: { type: String, required: true, unique: true },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Library' },
  cost: { type: Number, default: null },
  refusalReason: { type: String, default: null },
  // New delivery fields
  deliveryDriver: { type: mongoose.Schema.Types.ObjectId, ref: 'DeliveryDriver' },
  deliveryStatus: {
    type: String,
    enum: ['pending', 'accepted', 'picked_up', 'delivered'],
    default: 'pending'
  },
  deliveryFee: { type: Number, default: 50 },
  amountPaidToLibrary: { type: Number, default: null },
  libraryPaid: { type: Boolean, default: false },
  clientPaid: { type: Boolean, default: false }
}, {
  timestamps: true
});

orderSchema.index({ location: '2dsphere' });

module.exports = mongoose.model('Order', orderSchema);