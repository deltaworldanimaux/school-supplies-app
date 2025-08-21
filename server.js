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
const MONGODB_URI = "mongodb+srv://deltaworldanimaux:SYQ0SLzI97c73EKS@supply.v7ebphf.mongodb.net/school_supplies?retryWrites=true&w=majority&appName=supply";
let clients = [];
const TelegramBot = require('node-telegram-bot-api');
const TELEGRAM_BOT_TOKEN = '8282280616:AAEILrAJbJ_HnSjPO01HENUYrMHNuoU4cTs';
const TELEGRAM_CHAT_ID = '7779679746';
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, {polling: false});

// Function to send Telegram notification
async function sendTelegramNotification(message) {
  try {
    await bot.sendMessage(TELEGRAM_CHAT_ID, message);
    console.log('Telegram notification sent');
  } catch (error) {
    console.error('Error sending Telegram notification:', error);
  }
}
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

const uploadToImgBB = async (filePath) => {
  try {
    const formData = new FormData();
    const imageBuffer = fs.readFileSync(filePath);
    formData.append('image', imageBuffer.toString('base64'));
    
    const response = await fetch(`https://api.imgbb.com/1/upload?key=4398dfbf7f2440db0ca2089e394b4166`, {
      method: 'POST',
      body: formData
    });
    
    const data = await response.json();
    
    if (data.success) {
      return data.data.url;
    } else {
      throw new Error(data.error.message || 'ImgBB upload failed');
    }
  } catch (error) {
    console.error('ImgBB upload error:', error);
    // Fallback to local storage if ImgBB fails
    return `uploads/${path.basename(filePath)}`;
  }
};

// Submit order
app.post('/api/orders', upload.single('suppliesList'), async (req, res) => {
  try {
    const { parentName, phone, studentName, grade, latitude, longitude } = req.body;
    
    // Validate all required fields including file
    if (!parentName || !phone || !studentName || !grade || !latitude || !longitude || !req.file) {
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ message: 'جميع الحقول مطلوبة بما في ذلك الملف والموقع' });
    }
    
    let fileUrl;
    try {
      // Try to upload to ImgBB
      fileUrl = await uploadToImgBB(req.file.path);
      
      // If successful, delete local file
      if (fileUrl.startsWith('http')) {
        fs.unlinkSync(req.file.path);
      }
    } catch (uploadError) {
      console.error('File upload error:', uploadError);
      // Fallback to local file path
      fileUrl = `uploads/${req.file.filename}`;
    }
    
    // Generate a proper order number (format: ORD-YYYYMMDD-XXXX)
    const now = new Date();
    const datePart = now.toISOString().slice(0, 10).replace(/-/g, '');
    const randomPart = Math.floor(1000 + Math.random() * 9000);
    const orderNumber = `ORD-${datePart}-${randomPart}`;
    
    const order = new Order({
      parentName,
      phone,
      studentName,
      grade,
      location: {
        type: 'Point',
        coordinates: [parseFloat(longitude), parseFloat(latitude)]
      },
      suppliesList: fileUrl,
      status: 'pending',
      orderNumber: orderNumber // Store the order number
    });
    
    await order.save();
    // Send Telegram notification for new order
const newOrderMessage = `🆕 New Order Received!\nOrder Number: ${orderNumber}\nParent: ${parentName}\nStudent: ${studentName}\nGrade: ${grade}\nPhone: ${phone}`;
sendTelegramNotification(newOrderMessage);

// Send event to all connected admin clients
sendEventToClients('new-order', { 
  message: 'New order placed', 
  orderId: order._id,
  orderNumber: orderNumber
});
    res.status(201).json({ 
      message: 'تم إرسال الطلب بنجاح!', 
      orderId: order._id,
      orderNumber: orderNumber // Return the order number
    });
  } catch (error) {
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    console.error('Order submission error:', error);
    res.status(500).json({ message: 'خطأ في إرسال الطلب', error: error.message });
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

app.get('/api/orders/events', authenticateAdmin, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const clientId = Date.now();
  const newClient = {
    id: clientId,
    res
  };
  clients.push(newClient);

  req.on('close', () => {
    console.log(`${clientId} Connection closed`);
    clients = clients.filter(client => client.id !== clientId);
  });
});

// Function to send events to all connected clients
function sendEventToClients(event, data) {
  clients.forEach(client => client.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
}
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

// Initialize admin user (run once) - POST method only
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

// Add a GET endpoint for easier initialization from browser
app.get('/api/admin/init', async (req, res) => {
  res.json({ 
    message: 'Please use POST method to initialize admin account',
    example: 'curl -X POST https://your-repl.url/api/admin/init'
  });
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
  console.log('Make sure to run POST /api/admin/init to create the default admin account');
});

// Handle process termination
process.on('SIGINT', async () => {
  console.log('Shutting down server...');
  await mongoose.connection.close();
  process.exit(0);
});