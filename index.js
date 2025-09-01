const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const { Server } = require('socket.io');
const http = require('http');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');

const db = require('./db');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://cdn.socket.io"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Session configuration
app.use(session({
  secret: 'heropixel-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false, // Set to true in production with HTTPS
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// View engine
app.set('view engine', 'ejs');
app.set('views', './views');

// Email configuration (configure with your SMTP settings)
const transporter = nodemailer.createTransport({
  service: 'gmail', // or your email service
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  }
});

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = `./uploads/${req.session.user.username}`;
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB per file
  }
});

// Middleware functions
const requireAuth = (req, res, next) => {
  if (!req.session.user || !req.session.user.verified) {
    return res.redirect('/login');
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send('Access denied');
  }
  next();
};

// Routes

// Home route
app.get('/', (req, res) => {
  if (req.session.user && req.session.user.verified) {
    return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

// Authentication routes
app.get('/register', (req, res) => {
  res.render('auth/register', { error: null, success: null });
});

app.post('/register', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('auth/register', { 
      error: 'Invalid input. Username must be at least 3 characters, email must be valid, password at least 6 characters.', 
      success: null 
    });
  }

  const { username, email, password } = req.body;

  db.createUser(username, email, password, (err, result) => {
    if (err) {
      let errorMsg = 'Registration failed';
      if (err.message.includes('UNIQUE constraint')) {
        errorMsg = 'Username or email already exists';
      }
      return res.render('auth/register', { error: errorMsg, success: null });
    }

    // Create verification token
    const token = uuidv4();
    const expires = Date.now() + 15 * 60 * 1000; // 15 minutes

    db.createVerificationToken(result.id, token, expires, (err) => {
      if (err) {
        console.error('Failed to create verification token:', err);
        return res.render('auth/register', { 
          error: 'Registration failed', 
          success: null 
        });
      }

      // Send verification email
      const verifyUrl = `http://localhost:3001/verify/${token}`;
      const mailOptions = {
        from: process.env.EMAIL_USER || 'noreply@heropixel.com',
        to: email,
        subject: 'Verify Your HeroPixel Account',
        html: `
          <h2>Welcome to HeroPixel Network!</h2>
          <p>Please click the link below to verify your account:</p>
          <a href="${verifyUrl}">Verify Account</a>
          <p>This link expires in 15 minutes.</p>
        `
      };

      transporter.sendMail(mailOptions, (err) => {
        if (err) {
          console.error('Failed to send verification email:', err);
        }
        res.render('auth/register', { 
          error: null, 
          success: 'Registration successful! Please check your email to verify your account.' 
        });
      });
    });
  });
});

app.get('/verify/:token', (req, res) => {
  const token = req.params.token;

  db.getVerificationToken(token, (err, tokenData) => {
    if (err || !tokenData) {
      return res.render('auth/login', { 
        error: 'Invalid or expired verification token', 
        success: null 
      });
    }

    db.verifyUser(tokenData.user_id, (err) => {
      if (err) {
        return res.render('auth/login', { 
          error: 'Verification failed', 
          success: null 
        });
      }

      db.deleteVerificationToken(token, () => {
        res.render('auth/login', { 
          error: null, 
          success: 'Account verified successfully! You can now log in.' 
        });
      });
    });
  });
});

app.get('/login', (req, res) => {
  res.render('auth/login', { error: null, success: null });
});

app.post('/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('auth/login', { error: 'Invalid email or password', success: null });
  }

  const { email, password } = req.body;

  db.getUserByEmail(email, (err, user) => {
    if (err || !user) {
      return res.render('auth/login', { error: 'Invalid email or password', success: null });
    }

    if (!user.verified) {
      return res.render('auth/login', { 
        error: 'Please verify your email before logging in', 
        success: null 
      });
    }

    if (!bcrypt.compareSync(password, user.password)) {
      return res.render('auth/login', { error: 'Invalid email or password', success: null });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      verified: user.verified
    };

    res.redirect('/dashboard');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.get('/forgot-password', (req, res) => {
  res.render('auth/forgot-password', { error: null, success: null });
});

app.post('/forgot-password', [
  body('email').isEmail().normalizeEmail()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('auth/forgot-password', { error: 'Invalid email', success: null });
  }

  const { email } = req.body;

  db.getUserByEmail(email, (err, user) => {
    if (err || !user) {
      return res.render('auth/forgot-password', { 
        error: null, 
        success: 'If that email exists, a reset link has been sent.' 
      });
    }

    const token = uuidv4();
    const expires = Date.now() + 15 * 60 * 1000; // 15 minutes

    db.setResetToken(user.id, token, expires, (err) => {
      if (err) {
        return res.render('auth/forgot-password', { 
          error: 'Failed to generate reset token', 
          success: null 
        });
      }

      const resetUrl = `http://localhost:3001/reset/${token}`;
      const mailOptions = {
        from: process.env.EMAIL_USER || 'noreply@heropixel.com',
        to: email,
        subject: 'Password Reset - HeroPixel Network',
        html: `
          <h2>Password Reset Request</h2>
          <p>Click the link below to reset your password:</p>
          <a href="${resetUrl}">Reset Password</a>
          <p>This link expires in 15 minutes.</p>
        `
      };

      transporter.sendMail(mailOptions, (err) => {
        if (err) {
          console.error('Failed to send reset email:', err);
        }
        res.render('auth/forgot-password', { 
          error: null, 
          success: 'If that email exists, a reset link has been sent.' 
        });
      });
    });
  });
});

app.get('/reset/:token', (req, res) => {
  const token = req.params.token;

  db.getUserByResetToken(token, (err, user) => {
    if (err || !user) {
      return res.render('auth/login', { 
        error: 'Invalid or expired reset token', 
        success: null 
      });
    }

    res.render('auth/reset-password', { token, error: null });
  });
});

app.post('/reset/:token', [
  body('password').isLength({ min: 6 }),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Passwords do not match');
    }
    return value;
  })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('auth/reset-password', { 
      token: req.params.token, 
      error: 'Password must be at least 6 characters and passwords must match' 
    });
  }

  const token = req.params.token;
  const { password } = req.body;

  db.getUserByResetToken(token, (err, user) => {
    if (err || !user) {
      return res.render('auth/login', { 
        error: 'Invalid or expired reset token', 
        success: null 
      });
    }

    db.updateUserPassword(user.id, password, (err) => {
      if (err) {
        return res.render('auth/reset-password', { 
          token, 
          error: 'Failed to update password' 
        });
      }

      res.render('auth/login', { 
        error: null, 
        success: 'Password updated successfully! You can now log in.' 
      });
    });
  });
});

// Dashboard
app.get('/dashboard', requireAuth, (req, res) => {
  res.render('dashboard', { user: req.session.user });
});

// Chat
app.get('/chat', requireAuth, (req, res) => {
  db.getRecentMessages(50, (err, messages) => {
    if (err) {
      console.error('Failed to get messages:', err);
      messages = [];
    }
    res.render('chat', { user: req.session.user, messages });
  });
});

app.post('/chat/send', requireAuth, [
  body('message').notEmpty().trim().escape()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.json({ success: false, error: 'Message cannot be empty' });
  }

  const { message } = req.body;
  const user = req.session.user;

  db.addMessage(user.id, user.username, message, (err) => {
    if (err) {
      return res.json({ success: false, error: 'Failed to send message' });
    }

    // Emit to all connected clients
    io.emit('newMessage', {
      username: user.username,
      message: message,
      timestamp: new Date().toISOString()
    });

    res.json({ success: true });
  });
});

// Storage
app.get('/storage', requireAuth, (req, res) => {
  db.getUserFiles(req.session.user.id, (err, userFiles) => {
    if (err) {
      console.error('Failed to get user files:', err);
      userFiles = [];
    }

    db.getPublicFiles((err, publicFiles) => {
      if (err) {
        console.error('Failed to get public files:', err);
        publicFiles = [];
      }

      db.getUserStorageUsed(req.session.user.id, (err, usage) => {
        if (err) {
          console.error('Failed to get storage usage:', err);
          usage = { total: 0 };
        }

        const storageLimit = req.session.user.role === 'admin' ? -1 : 5 * 1024 * 1024 * 1024; // 5GB for users, unlimited for admin
        const storageUsed = usage.total;

        res.render('storage', { 
          user: req.session.user, 
          userFiles, 
          publicFiles, 
          storageUsed,
          storageLimit
        });
      });
    });
  });
});

app.post('/storage/upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.redirect('/storage?error=No file selected');
  }

  const user = req.session.user;
  const visibility = req.body.visibility || 'private';

  // Check storage quota for non-admin users
  if (user.role !== 'admin') {
    db.getUserStorageUsed(user.id, (err, usage) => {
      if (err) {
        console.error('Failed to check storage:', err);
        return res.redirect('/storage?error=Upload failed');
      }

      const storageLimit = 5 * 1024 * 1024 * 1024; // 5GB
      if (usage.total + req.file.size > storageLimit) {
        // Delete the uploaded file
        fs.unlinkSync(req.file.path);
        return res.redirect('/storage?error=Storage quota exceeded');
      }

      // Proceed with file storage
      storeFile();
    });
  } else {
    storeFile();
  }

  function storeFile() {
    db.addFile(user.id, req.file.filename, req.file.originalname, req.file.size, visibility, (err) => {
      if (err) {
        console.error('Failed to store file info:', err);
        fs.unlinkSync(req.file.path);
        return res.redirect('/storage?error=Upload failed');
      }

      res.redirect('/storage?success=File uploaded successfully');
    });
  }
});

app.post('/storage/delete/:id', requireAuth, (req, res) => {
  const fileId = req.params.id;
  const user = req.session.user;

  db.deleteFile(fileId, (err, file) => {
    if (err) {
      return res.json({ success: false, error: 'Failed to delete file' });
    }

    // Check if user owns the file or is admin
    if (file.user_id !== user.id && user.role !== 'admin') {
      return res.json({ success: false, error: 'Access denied' });
    }

    // Delete physical file
    const filePath = `./uploads/${user.role === 'admin' ? file.username || 'unknown' : user.username}/${file.filename}`;
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    res.json({ success: true });
  });
});

app.get('/download/:id', requireAuth, (req, res) => {
  const fileId = req.params.id;
  const user = req.session.user;

  db.getAllFiles((err, files) => {
    if (err) {
      return res.status(500).send('Server error');
    }

    const file = files.find(f => f.id == fileId);
    if (!file) {
      return res.status(404).send('File not found');
    }

    // Check permissions
    if (file.visibility === 'private' && file.user_id !== user.id && user.role !== 'admin') {
      return res.status(403).send('Access denied');
    }

    const filePath = `./uploads/${file.username}/${file.filename}`;
    if (!fs.existsSync(filePath)) {
      return res.status(404).send('File not found on disk');
    }

    res.download(filePath, file.original_name);
  });
});

// Admin routes
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  db.getAllUsers((err, users) => {
    if (err) {
      console.error('Failed to get users:', err);
      users = [];
    }

    db.getAllMessages((err, messages) => {
      if (err) {
        console.error('Failed to get messages:', err);
        messages = [];
      }

      db.getAllFiles((err, files) => {
        if (err) {
          console.error('Failed to get files:', err);
          files = [];
        }

        res.render('admin', { 
          user: req.session.user, 
          users, 
          messages, 
          files 
        });
      });
    });
  });
});

app.post('/admin/user/:id/role', requireAuth, requireAdmin, (req, res) => {
  const userId = req.params.id;
  const { role } = req.body;

  if (!['user', 'admin'].includes(role)) {
    return res.json({ success: false, error: 'Invalid role' });
  }

  db.updateUserRole(userId, role, (err) => {
    if (err) {
      return res.json({ success: false, error: 'Failed to update role' });
    }
    res.json({ success: true });
  });
});

app.post('/admin/user/:id/delete', requireAuth, requireAdmin, (req, res) => {
  const userId = req.params.id;

  // Prevent admin from deleting themselves
  if (userId == req.session.user.id) {
    return res.json({ success: false, error: 'Cannot delete your own account' });
  }

  db.deleteUser(userId, (err) => {
    if (err) {
      return res.json({ success: false, error: 'Failed to delete user' });
    }
    res.json({ success: true });
  });
});

app.post('/admin/message/:id/delete', requireAuth, requireAdmin, (req, res) => {
  const messageId = req.params.id;

  db.deleteMessage(messageId, (err) => {
    if (err) {
      return res.json({ success: false, error: 'Failed to delete message' });
    }
    res.json({ success: true });
  });
});

app.post('/admin/file/:id/delete', requireAuth, requireAdmin, (req, res) => {
  const fileId = req.params.id;

  db.deleteFile(fileId, (err, file) => {
    if (err) {
      return res.json({ success: false, error: 'Failed to delete file' });
    }

    // Delete physical file
    const filePath = `./uploads/${file.username}/${file.filename}`;
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    res.json({ success: true });
  });
});

// Socket.IO for real-time chat
io.on('connection', (socket) => {
  console.log('User connected to chat');

  socket.on('disconnect', () => {
    console.log('User disconnected from chat');
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// 404 handler
app.use((req, res) => {
  res.status(404).send('Page not found');
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`HeroPixel Network Panel running on port ${PORT}`);
  console.log(`Visit: http://localhost:${PORT}`);
});