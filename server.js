const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// MongoDB Connection
const MONGODB_URI = "mongodb+srv://deltaworldanimaux:SYQ0SLzI97c73EKS@supply.v7ebphf.mongodb.net/?retryWrites=true&w=majority&appName=supply";

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('Connected to MongoDB Atlas');
})
.catch((error) => {
  console.error('MongoDB connection error:', error);
  process.exit(1); // Exit the process if connection fails
});

// MongoDB Models
const Order = require('./models/Order');
const Admin = require('./models/Admin');

// File upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|pdf/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb('Error: Images and PDFs only!');
    }
  }
});

// Authentication middleware
const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'Access denied. No token provided.' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
    const admin = await Admin.findById(decoded.id);
    
    if (!admin) {
      return res.status(401).json({ message: 'Invalid token.' });
    }
    
    req.admin = admin;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token.' });
  }
};

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve admin page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Submit order
app.post('/api/orders', upload.single('suppliesList'), async (req, res) => {
  try {
    const { parentName, phone, studentName, grade, latitude, longitude } = req.body;
    
    const order = new Order({
      parentName,
      phone,
      studentName,
      grade,
      location: {
        type: 'Point',
        coordinates: [parseFloat(longitude), parseFloat(latitude)]
      },
      suppliesList: req.file ? req.file.filename : null,
      status: 'pending'
    });
    
    await order.save();
    res.status(201).json({ 
      message: 'Order submitted successfully!', 
      orderId: order._id,
      orderNumber: Math.floor(1000 + Math.random() * 9000)
    });
  } catch (error) {
    console.error('Order submission error:', error);
    res.status(500).json({ message: 'Error submitting order', error: error.message });
  }
});

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Check if admin exists
    const admin = await Admin.findOne({ username });
    if (!admin) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Generate token
    const token = jwt.sign(
      { id: admin._id }, 
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );
    
    res.json({ 
      token, 
      admin: { id: admin._id, username: admin.username },
      message: 'Login successful'
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get all orders (admin only)
app.get('/api/orders', authenticateAdmin, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    console.error('Fetch orders error:', error);
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
});

// Update order status (admin only)
app.put('/api/orders/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    res.json({ message: 'Order status updated', order });
  } catch (error) {
    console.error('Update order error:', error);
    res.status(500).json({ message: 'Error updating order', error: error.message });
  }
});

// Get order by ID (admin only)
app.get('/api/orders/:id', authenticateAdmin, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    res.json(order);
  } catch (error) {
    console.error('Fetch order error:', error);
    res.status(500).json({ message: 'Error fetching order', error: error.message });
  }
});

// Delete order (admin only)
app.delete('/api/orders/:id', authenticateAdmin, async (req, res) => {
  try {
    const order = await Order.findByIdAndDelete(req.params.id);
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    // Delete associated file if exists
    if (order.suppliesList) {
      fs.unlink(path.join(__dirname, 'uploads', order.suppliesList), (err) => {
        if (err) console.error('Error deleting file:', err);
      });
    }
    
    res.json({ message: 'Order deleted successfully' });
  } catch (error) {
    console.error('Delete order error:', error);
    res.status(500).json({ message: 'Error deleting order', error: error.message });
  }
});

// Initialize admin user (run once)
app.post('/api/admin/init', async (req, res) => {
  try {
    // Check if admin already exists
    const existingAdmin = await Admin.findOne();
    if (existingAdmin) {
      return res.status(400).json({ message: 'Admin already exists' });
    }
    
    // Create default admin
    const hashedPassword = await bcrypt.hash('admin123', 12);
    const admin = new Admin({
      username: 'admin',
      password: hashedPassword
    });
    
    await admin.save();
    res.json({ 
      message: 'Default admin created', 
      username: 'admin', 
      password: 'admin123',
      note: 'Please change the password after first login'
    });
  } catch (error) {
    console.error('Admin init error:', error);
    res.status(500).json({ message: 'Error creating admin', error: error.message });
  }
});

// Change admin password
app.post('/api/admin/change-password', authenticateAdmin, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    // Check current password
    const isMatch = await bcrypt.compare(currentPassword, req.admin.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }
    
    // Update password
    req.admin.password = await bcrypt.hash(newPassword, 12);
    await req.admin.save();
    
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ message: 'Error changing password', error: error.message });
  }
});

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Local: http://localhost:${PORT}`);
  console.log('Make sure to run /api/admin/init to create the default admin account');
});

// Handle process termination
process.on('SIGINT', async () => {
  console.log('Shutting down server...');
  await mongoose.connection.close();
  process.exit(0);
});