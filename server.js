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
let deliveryClients = [];
// MongoDB Models
const Order = require('./models/Order');
const Admin = require('./models/Admin');
const Library = require('./models/Library');
const DeliveryMan = require('./models/DeliveryMan');
const GITHUB_TOKEN = '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';
const GITHUB_REPO = 'deltaworldanimaux/myproject3';
const GITHUB_BRANCH = 'main';
const TelegramBot = require('node-telegram-bot-api');
const TELEGRAM_BOT_TOKEN = '8282280616:AAEILrAJbJ_HnSjPO01HENUYrMHNuoU4cTs';
const TELEGRAM_CHAT_ID = '7779679746';
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true });
bot.on('message', async (msg) => {
console.log('📩 Incoming message:', msg.text, 'from', msg.chat.id);


const chatId = msg.chat.id;
const text = msg.text;


if (!text) return;


if (text === '/start') {
return bot.sendMessage(chatId, 'مرحباً! استخدم\n/register [username] [password]');
}


if (text.startsWith('/register')) {
const [ , username, ...passParts ] = text.split(' ');
const password = passParts.join(' ');


if (!username || !password) {
return bot.sendMessage(chatId, '❌ الصيغة غير صحيحة. استخدم: /register username password');
}


try {
const library = await Library.findOne({ username });
if (!library) return bot.sendMessage(chatId, '❌ اسم المستخدم غير صحيح');


const valid = await bcrypt.compare(password, library.password);
if (!valid) return bot.sendMessage(chatId, '❌ كلمة المرور غير صحيحة');


library.telegramChatId = chatId;
await library.save();


return bot.sendMessage(chatId, `✅ تم ربط المكتبة: ${library.name}`);
} catch (err) {
console.error('Telegram register error:', err);
return bot.sendMessage(chatId, '⚠️ خطأ داخلي، حاول لاحقاً');
}
}
});

async function sendLibraryNotification(libraryId, message) {
try {
const library = await Library.findById(libraryId);
if (library?.telegramChatId) {
await bot.sendMessage(library.telegramChatId, message);
}
} catch (err) {
console.error('Error sending library notification:', err);
}
}
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
            // Check if file is PDF
            const isPDF = req.file.originalname.toLowerCase().endsWith('.pdf');
            
            if (isPDF) {
                // Upload PDF to GitHub
                fileUrl = await uploadToGitHub(req.file.path, req.file.originalname);
                
                // Delete local file after successful upload
                fs.unlinkSync(req.file.path);
            } else {
                // For images, use ImgBB as before
                fileUrl = await uploadToImgBB(req.file.path);
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

// Delivery Man authentication middleware
const authenticateDeliveryMan = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'Access denied' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
    const deliveryMan = await DeliveryMan.findById(decoded.id);
    
    if (!deliveryMan) return res.status(401).json({ message: 'Invalid token' });
    
    req.deliveryMan = deliveryMan;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token' });
  }
};

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
    const orders = await Order.find().sort({ createdAt: -1 }).populate('deliveryMan', 'name phone');
    res.json(orders);
  } catch (error) {
    console.error('Fetch orders error:', error);
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
});

app.get('/api/delivery/profile', authenticateDeliveryMan, async (req, res) => {
  const deliveryMan = await DeliveryMan.findById(req.deliveryMan._id)
    .populate('currentOrder', 'orderNumber');
  
  res.json({
    id: deliveryMan._id,
    name: deliveryMan.name,
    score: deliveryMan.score,
    hasActiveOrder: !!deliveryMan.currentOrder,
    currentOrder: deliveryMan.currentOrder
  });
});

app.get('/api/delivery/events', async (req, res) => {
  try {
    const token = req.query.token;
    
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
    const deliveryMan = await DeliveryMan.findById(decoded.id);
    
    if (!deliveryMan) {
      return res.status(401).json({ message: 'Invalid token' });
    }
    
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const clientId = Date.now();
    const newClient = {
      id: clientId,
      res,
      deliveryManId: deliveryMan._id
    };
    deliveryClients.push(newClient);

    req.on('close', () => {
      deliveryClients = deliveryClients.filter(client => client.id !== clientId);
    });
  } catch (error) {
    res.status(400).json({ message: 'Invalid token' });
  }
});

// Function to send events to all delivery clients
function sendEventToDeliveryClients(event, data) {
  deliveryClients.forEach(client => client.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
}

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
    
    let query = Order.findById(req.params.id).populate('deliveryMan', 'name phone');
    
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
    const { name, phone, latitude, longitude, username, password, telegramChatId } = req.body;
    
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
      plainPassword: password,
      telegramChatId: telegramChatId || null
    });
    
    await library.save();
    
    res.status(201).json({
      message: 'Library created successfully',
      library: {
        _id: library._id,
        name: library.name,
        phone: library.phone,
        username: library.username,
        plainPassword: library.plainPassword,
        telegramChatId: library.telegramChatId
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
    
    // Get the library details
    const library = await Library.findById(libraryId);
    if (!library) {
      return res.status(404).json({ message: 'Library not found' });
    }
    
    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { 
        status: 'confirmed',
        assignedTo: libraryId 
      },
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    // Send Telegram notification to the library if they have a chat ID
    if (library.telegramChatId) {
      try {
        await sendLibraryNotification(libraryId, `🆕 تم تعيين طلب جديد!\nرقم الطلب: ${order.orderNumber}\nاسم ولي الأمر: ${order.parentName}\nاسم التلميذ: ${order.studentName}\nالمستوى الدراسي: ${order.grade}`);
        console.log('Telegram notification sent to library');
      } catch (telegramError) {
        console.error('Error sending Telegram notification to library:', telegramError);
        // Don't fail the request if Telegram notification fails
      }
    }
    
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

app.get('/api/library/profile', authenticateLibrary, async (req, res) => {
  res.json({
    id: req.library._id,
    name: req.library.name,
    phone: req.library.phone
  });
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

app.post('/api/report-issue', authenticateDeliveryMan, async (req, res) => {
    try {
        const { type, description, deliveryManName, orderNumber, orderId } = req.body;
        
        // Format Telegram message with more details
        const issueType = type === 'payment' ? 'مشكلة في الدفع للمكتبة' : 'مشكلة في التسليم للعميل';
        const message = `🚨 بلاغ مشكلة في التوصيل\n\n` +
                       `نوع المشكلة: ${issueType}\n` +
                       `وصف المشكلة: ${description}\n` +
                       `اسم المندوب: ${deliveryManName}\n` +
                       `رقم الطلب: ${orderNumber}\n` +
                       `معرف الطلب: ${orderId}\n\n` +
                       `يرجى التواصل مع المندوب لحل المشكلة.`;
        
        // Send Telegram notification
        await sendTelegramNotification(message);
        
        res.json({ message: 'Issue reported successfully' });
    } catch (error) {
        console.error('Error reporting issue:', error);
        res.status(500).json({ message: 'Error reporting issue', error: error.message });
    }
});

// Create delivery man (admin only)
app.post('/api/delivery-men', authenticateAdmin, async (req, res) => {
  try {
    const { name, phone, username, password } = req.body;
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const deliveryMan = new DeliveryMan({
      name,
      phone,
      username,
      password: hashedPassword
    });
    
    await deliveryMan.save();
    
    res.status(201).json({
      message: 'Delivery man created successfully',
      deliveryMan: {
        _id: deliveryMan._id,
        name: deliveryMan.name,
        phone: deliveryMan.phone,
        username: deliveryMan.username,
        password: password // Return plain text password for admin reference
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating delivery man', error: error.message });
  }
});

// Get all delivery men (admin only)
app.get('/api/delivery-men', authenticateAdmin, async (req, res) => {
  try {
    const deliveryMen = await DeliveryMan.find().select('-password');
    res.json(deliveryMen);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching delivery men', error: error.message });
  }
});

// Get order details for delivery man
app.get('/api/delivery/orders/:id', authenticateDeliveryMan, async (req, res) => {
  try {
    const order = await Order.findOne({
      _id: req.params.id,
      deliveryMan: req.deliveryMan._id
    }).populate('assignedTo', 'name phone location');

    if (!order) {
      return res.status(404).json({ message: 'Order not found or not assigned to you' });
    }

    res.json(order);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching order', error: error.message });
  }
});

// Update delivery man (admin only)
app.put('/api/delivery-men/:id', authenticateAdmin, async (req, res) => {
  try {
    const { name, phone, username, password } = req.body;
    
    const updateData = { name, phone, username };
    
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 12);
      updateData.password = hashedPassword;
    }
    
    const deliveryMan = await DeliveryMan.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    ).select('-password');
    
    if (!deliveryMan) {
      return res.status(404).json({ message: 'Delivery man not found' });
    }
    
    res.json({ message: 'Delivery man updated successfully', deliveryMan });
  } catch (error) {
    res.status(500).json({ message: 'Error updating delivery man', error: error.message });
  }
});

// Delete delivery man (admin only)
app.delete('/api/delivery-men/:id', authenticateAdmin, async (req, res) => {
  try {
    const deliveryMan = await DeliveryMan.findByIdAndDelete(req.params.id);
    
    if (!deliveryMan) {
      return res.status(404).json({ message: 'Delivery man not found' });
    }
    
    res.json({ message: 'Delivery man deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting delivery man', error: error.message });
  }
});

// Delivery man login
app.post('/api/delivery/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const deliveryMan = await DeliveryMan.findOne({ username });
    
    if (!deliveryMan || !(await bcrypt.compare(password, deliveryMan.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: deliveryMan._id },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );
    
    res.json({ 
      token, 
      deliveryMan: { 
        id: deliveryMan._id, 
        name: deliveryMan.name,
        score: deliveryMan.score
      } 
    });
  } catch (error) {
    res.status(500).json({ message: 'Login error', error: error.message });
  }
});

// Assign order to delivery man
app.post('/api/orders/:id/assign-delivery', authenticateAdmin, async (req, res) => {
  try {
    const { deliveryManId } = req.body;
    
    const deliveryMan = await DeliveryMan.findById(deliveryManId);
    if (!deliveryMan) {
      return res.status(404).json({ message: 'Delivery man not found' });
    }
    
    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { 
        deliveryMan: deliveryManId,
        deliveryStatus: 'assigned'
      },
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    res.json({ message: 'Order assigned to delivery man', order });
  } catch (error) {
    res.status(500).json({ message: 'Error assigning order', error: error.message });
  }
});

// Get available orders for delivery (status: ready)
app.get('/api/delivery/available-orders', authenticateDeliveryMan, async (req, res) => {
  try {
    const orders = await Order.find({
      status: 'ready', // Already set when library completes order
      deliveryStatus: 'pending', // Only pending deliveries
      $or: [
        { deliveryMan: { $exists: false } },
        { deliveryMan: null }
      ]
    }).populate('assignedTo', 'name phone location');

    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
});

// Delivery man picks up order
app.put('/api/delivery/orders/:id/pickup', authenticateDeliveryMan, async (req, res) => {
  try {
    // Check if delivery man already has an active order
    if (req.deliveryMan.currentOrder) {
      return res.status(400).json({ message: 'لديك طلب نشط بالفعل. يجب تسليمه أولاً' });
    }

    const order = await Order.findOneAndUpdate(
      {
        _id: req.params.id,
        status: 'ready',
        deliveryStatus: 'pending'
      },
      {
        deliveryMan: req.deliveryMan._id,
        deliveryStatus: 'assigned'
      },
      { new: true }
    ).populate('assignedTo', 'name phone location');

    if (!order) {
      return res.status(404).json({ message: 'الطلب غير متاح أو تم أخذه' });
    }

    // Update delivery man's current order
    await DeliveryMan.findByIdAndUpdate(
      req.deliveryMan._id,
      { currentOrder: order._id }
    );

    // Notify other delivery men
    sendEventToDeliveryClients('order-taken', {
      orderId: order._id,
      takenBy: req.deliveryMan._id
    });

    res.json({ message: 'تم تعيين الطلب لك بنجاح', order });
  } catch (error) {
    res.status(500).json({ message: 'خطأ في استلام الطلب', error: error.message });
  }
});

// Get orders for delivery man
app.get('/api/delivery/my-orders', authenticateDeliveryMan, async (req, res) => {
  try {
    const orders = await Order.find({ 
      deliveryMan: req.deliveryMan._id,
      deliveryStatus: { $in: ['assigned', 'picked_up'] }
    }).populate('assignedTo', 'name phone location').populate('deliveryMan', 'name phone');
    
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
});

// Delivery man marks order as delivered
app.put('/api/delivery/orders/:id/deliver', authenticateDeliveryMan, async (req, res) => {
  try {
    const order = await Order.findOneAndUpdate(
      { 
        _id: req.params.id, 
        deliveryMan: req.deliveryMan._id,
        deliveryStatus: 'assigned'
      },
      { 
        deliveryStatus: 'delivered',
        status: 'delivered'
      },
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ message: 'الطلب غير موجود أو غير معين لك' });
    }
    
    // Increase score and clear current order
    await DeliveryMan.findByIdAndUpdate(
      req.deliveryMan._id,
      { 
        $inc: { score: 10 },
        $set: { currentOrder: null }
      }
    );
    
    res.json({ message: 'تم تسليم الطلب بنجاح', order });
  } catch (error) {
    res.status(500).json({ message: 'خطأ في تسليم الطلب', error: error.message });
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
    const { name, phone, latitude, longitude, username, password, telegramChatId } = req.body;
    
    const updateData = {
      name,
      phone,
      location: {
        type: 'Point',
        coordinates: [parseFloat(longitude), parseFloat(latitude)]
      },
      username,
      telegramChatId: telegramChatId || null
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
app.put('/api/library/orders/:id/refuse', authenticateLibrary, async (req, res) => {
  try {
    const { reason } = req.body;
    
    const order = await Order.findOneAndUpdate(
      { 
        _id: req.params.id, 
        assignedTo: req.library._id,
        status: { $in: ['confirmed', 'processing'] }
      },
      { 
        status: 'pending',
        refusalReason: reason,
        assignedTo: null // Remove assignment
      },
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ 
        message: 'الطلب غير موجود أو غير مخصص لهذه المكتبة أو لا يمكن رفضه في حالته الحالية' 
      });
    }
    
    // Send Telegram notification for refused order
    const refusalMessage = `❌ Order Refused!\nOrder Number: ${order.orderNumber}\nLibrary: ${req.library.name}\nReason: ${reason}`;
    sendTelegramNotification(refusalMessage);
    
    res.json({ message: 'تم رفض الطلب', order });
  } catch (error) {
    console.error('Refuse order error:', error);
    res.status(500).json({ message: 'خطأ في رفض الطلب', error: error.message });
  }
});
// Function to upload file to GitHub
async function uploadToGitHub(filePath, originalName) {
    try {
        // Read file content
        const fileContent = fs.readFileSync(filePath);
        const base64Content = fileContent.toString('base64');
        
        // Create filename with timestamp to avoid conflicts
        const timestamp = Date.now();
        const extension = path.extname(originalName);
        const fileName = `uploads/${timestamp}${extension}`;
        
        // GitHub API URL
        const apiUrl = `https://api.github.com/repos/${GITHUB_REPO}/contents/${fileName}`;
        
        // Request body
        const body = JSON.stringify({
            message: `Upload file: ${originalName}`,
            content: base64Content,
            branch: GITHUB_BRANCH
        });
        
        // Make request to GitHub API
        const response = await fetch(apiUrl, {
            method: 'PUT',
            headers: {
                'Authorization': `token ${GITHUB_TOKEN}`,
                'Content-Type': 'application/json',
                'User-Agent': 'School-Supplies-App'
            },
            body: body
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Return the raw content URL
            return data.content.download_url;
        } else {
            throw new Error(data.message || 'GitHub upload failed');
        }
    } catch (error) {
        console.error('GitHub upload error:', error);
        throw error;
    }
}
// Mark order as received
app.put('/api/library/orders/:id/receive', authenticateLibrary, async (req, res) => {
  try {
    const order = await Order.findOneAndUpdate(
      { _id: req.params.id, assignedTo: req.library._id },
      { status: 'processing' },
      { new: true }
    );
    
    res.json({ message: 'تم قبول الطلب', order });
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
    
    // Send Telegram notification for completed order
    const readyMessage = `✅ Order Ready!\nOrder Number: ${order.orderNumber}\nLibrary: ${req.library.name}\nCost: ${cost} MAD`;
    sendTelegramNotification(readyMessage);
    
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