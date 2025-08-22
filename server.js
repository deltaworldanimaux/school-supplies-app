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
const Library = require('./models/Library');

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
    // Add validation for new status values
    const validStatuses = ['pending', 'confirmed', 'processing', 'ready', 'delivered'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }
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
    // Check if the ID is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid order ID format' });
    }
    
    let query = Order.findById(req.params.id);
    
    // Check if populate is requested
    if (req.query.populate === 'assignedTo') {
      query = query.populate('assignedTo', 'name phone');
    }
    
    const order = await query.exec();
    
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
    // Check if the ID is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid order ID format' });
    }
    
    const order = await Order.findByIdAndDelete(req.params.id);
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    // Delete associated file only if it exists locally (not ImgBB URL)
    if (order.suppliesList && !order.suppliesList.startsWith('http')) {
      fs.unlink(path.join(__dirname, order.suppliesList), (err) => {
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
    const hashedPassword = await bcrypt.hash('Sbvd9vtc@me', 12);
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

// Library creation endpoint
app.post('/api/libraries', authenticateAdmin, async (req, res) => {
  try {
    const { name, phone, latitude, longitude, username, password } = req.body;
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const library = new Library({
      name,
      phone,
      location: {
        type: 'Point',
        coordinates: [parseFloat(longitude), parseFloat(latitude)]
      },
      username,
      password: hashedPassword,
      plainPassword: password // Store plain password
    });
    
    await library.save();
    
    res.status(201).json({
      message: 'Library created successfully',
      library: {
        _id: library._id,
        name: library.name,
        phone: library.phone,
        username: library.username,
        plainPassword: library.plainPassword
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating library', error: error.message });
  }
});

// Library login endpoint
app.post('/api/library/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const library = await Library.findOne({ username });
    
    if (!library || !(await bcrypt.compare(password, library.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: library._id },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );
    
    res.json({ token, library: { id: library._id, name: library.name } });
  } catch (error) {
    res.status(500).json({ message: 'Login error', error: error.message });
  }
});

// Assign order to library
app.post('/api/orders/:id/assign', authenticateAdmin, async (req, res) => {
  try {
    const { libraryId } = req.body;
    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { 
        status: 'confirmed',
        assignedTo: libraryId 
      },
      { new: true }
    );
    
    res.json({ message: 'Order assigned to library', order });
  } catch (error) {
    res.status(500).json({ message: 'Error assigning order', error: error.message });
  }
});
const authenticateLibrary = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'Access denied' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
    const library = await Library.findById(decoded.id);
    
    if (!library) return res.status(401).json({ message: 'Invalid token' });
    
    req.library = library;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token' });
  }
};
// Get library orders
app.get('/api/library/orders', authenticateLibrary, async (req, res) => {
  try {
    const orders = await Order.find({ 
      assignedTo: req.library._id,
      status: { $in: ['confirmed', 'processing'] } // Include confirmed status
    }).select('-phone -location');
    
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
});

app.get('/api/library/orders/:id', authenticateLibrary, async (req, res) => {
  try {
    const order = await Order.findOne({
      _id: req.params.id,
      assignedTo: req.library._id
    }).select('-phone -location');
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found or not assigned to this library' });
    }
    
    res.json(order);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching order', error: error.message });
  }
});

// Get all libraries (admin only)
app.get('/api/libraries', authenticateAdmin, async (req, res) => {
  try {
    const libraries = await Library.find().select('-password');
    res.json(libraries);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching libraries', error: error.message });
  }
});

app.put('/api/libraries/:id', authenticateAdmin, async (req, res) => {
  try {
    const { name, phone, latitude, longitude, username, password } = req.body;
    
    const updateData = {
      name,
      phone,
      location: {
        type: 'Point',
        coordinates: [parseFloat(longitude), parseFloat(latitude)]
      },
      username
    };
    
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 12);
      updateData.password = hashedPassword;
      updateData.plainPassword = password;
    }
    
    const library = await Library.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    ).select('-password');
    
    if (!library) {
      return res.status(404).json({ message: 'Library not found' });
    }
    
    res.json({ message: 'Library updated successfully', library });
  } catch (error) {
    res.status(500).json({ message: 'Error updating library', error: error.message });
  }
});
app.delete('/api/libraries/:id', authenticateAdmin, async (req, res) => {
  try {
    const library = await Library.findByIdAndDelete(req.params.id);
    
    if (!library) {
      return res.status(404).json({ message: 'Library not found' });
    }
    
    res.json({ message: 'Library deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting library', error: error.message });
  }
});
// Mark order as received
app.put('/api/library/orders/:id/receive', authenticateLibrary, async (req, res) => {
  try {
    const order = await Order.findOneAndUpdate(
      { _id: req.params.id, assignedTo: req.library._id },
      { status: 'processing' },
      { new: true }
    );
    
    res.json({ message: 'Order received', order });
  } catch (error) {
    res.status(500).json({ message: 'Error updating order', error: error.message });
  }
});

app.put('/api/library/orders/:id/deliver', authenticateLibrary, async (req, res) => {
  try {
    const order = await Order.findOneAndUpdate(
      { _id: req.params.id, assignedTo: req.library._id },
      { status: 'delivered' },
      { new: true }
    );
    
    res.json({ message: 'Order delivered', order });
  } catch (error) {
    res.status(500).json({ message: 'Error delivering order', error: error.message });
  }
});
// Mark order as completed
app.put('/api/library/orders/:id/complete', authenticateLibrary, async (req, res) => {
  try {
    const { cost } = req.body;
    
    // Validate cost - allow 0 cost if needed
    if (cost === undefined || cost === null || isNaN(cost) || cost < 0) {
      return res.status(400).json({ message: 'يرجى إدخال تكلفة صحيحة' });
    }
    
    const order = await Order.findOneAndUpdate(
      { 
        _id: req.params.id, 
        assignedTo: req.library._id,
        status: 'processing'
      },
      { 
        status: 'ready',
        cost: parseFloat(cost)
      },
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ 
        message: 'الطلب غير موجود أو غير مخصص لهذه المكتبة أو ليس في حالة معالجة' 
      });
    }
    
    res.json({ message: 'تم إكمال الطلب', order });
  } catch (error) {
    console.error('Complete order error:', error);
    res.status(500).json({ message: 'خطأ في إكمال الطلب', error: error.message });
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