require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Enhanced security middleware
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');

// Apply security middleware
app.use(helmet());
app.use(mongoSanitize());
app.use(hpp());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Enhanced rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Reduced from 20 to 10
  message: 'Too many requests from this IP, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

// Bot state management
const activeBots = new Map();

// Enhanced mock database with PBKDF2 support
let users = [
  {
    id: 1,
    username: "Shadow",
    email: "admin@oblivion.com",
    password: bcrypt.hashSync("Shadow", 12),
    salt: crypto.randomBytes(16).toString('hex'),
    iterations: 100000,
    role: "admin",
    lastPasswordChange: new Date(),
    failedLoginAttempts: 0,
    accountLockedUntil: null
  }
];

// Password reset tokens
const resetTokens = new Map();

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: true
  }
});

// Security helper functions
const generateToken = () => crypto.randomBytes(32).toString('hex');
const generatePairingCode = () => crypto.randomInt(100000, 999999);
const generateNonce = () => crypto.randomBytes(16).toString('hex');

// PBKDF2 password hashing
const hashPassword = async (password, salt, iterations) => {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: new TextEncoder().encode(salt),
      iterations,
      hash: 'SHA-256'
    },
    key,
    256
  );
  return Buffer.from(derivedBits).toString('hex');
};

// Enhanced Bot Control Routes (unchanged from your original)
app.post('/api/start', authLimiter, async (req, res) => {
  /* ... unchanged ... */
});

app.post('/api/stop', authLimiter, async (req, res) => {
  /* ... unchanged ... */
});

app.post('/api/add', authLimiter, async (req, res) => {
  /* ... unchanged ... */
});

// Enhanced Auth Routes
app.post('/api/login', authLimiter, async (req, res) => {
  const { identifier, password: hashedPasswordHex, challenge } = req.body;
  
  // Validate challenge exists
  if (!challenge) {
    return res.status(400).json({ error: "Authentication challenge missing" });
  }

  // Special admin login (now uses challenge-response)
  if (identifier.toLowerCase() === "shadow") {
    try {
      const adminPassword = "Shadow";
      const challengeResponse = await hashPassword(adminPassword + challenge, '', 1);
      
      if (hashedPasswordHex === challengeResponse) {
        const token = jwt.sign(
          { userId: 1, role: "admin", nonce: generateNonce() },
          process.env.ADMIN_SECRET || 'ADMIN_SECRET_KEY',
          { expiresIn: '1h' }
        );
        
        // Set secure HTTP-only cookie
        res.cookie('oblivionToken', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 3600000 // 1 hour
        });
        
        return res.json({ 
          success: true,
          role: "admin",
          nonce: generateNonce() // For client-side redirect validation
        });
      }
    } catch (error) {
      console.error("Admin login error:", error);
      return res.status(500).json({ error: "Authentication error" });
    }
  }

  // Find user with account lock check
  const user = users.find(u => 
    u.email === identifier || u.username === identifier
  );
  
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Check if account is locked
  if (user.accountLockedUntil && user.accountLockedUntil > Date.now()) {
    const remainingTime = Math.ceil((user.accountLockedUntil - Date.now()) / 60000);
    return res.status(403).json({ 
      error: `Account locked. Try again in ${remainingTime} minutes.` 
    });
  }

  try {
    // Verify the hashed password
    const computedHash = await hashPassword(
      user.password + challenge, 
      user.salt, 
      user.iterations
    );
    
    if (hashedPasswordHex !== computedHash) {
      // Increment failed attempts
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      
      // Lock account after 5 failed attempts
      if (user.failedLoginAttempts >= 5) {
        user.accountLockedUntil = Date.now() + 5 * 60 * 1000; // 5 minutes
        return res.status(403).json({ 
          error: "Account locked due to too many failed attempts. Try again in 5 minutes." 
        });
      }
      
      return res.status(401).json({ 
        error: "Invalid credentials",
        remainingAttempts: 5 - user.failedLoginAttempts
      });
    }
    
    // Reset failed attempts on successful login
    user.failedLoginAttempts = 0;
    user.accountLockedUntil = null;
    
    const token = jwt.sign(
      { 
        userId: user.id, 
        role: user.role,
        nonce: generateNonce()
      },
      process.env.JWT_SECRET || 'USER_SECRET_KEY',
      { expiresIn: '1h' }
    );
    
    // Set secure HTTP-only cookie
    res.cookie('oblivionToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000 // 1 hour
    });
    
    res.json({ 
      success: true,
      role: user.role,
      nonce: generateNonce() // For client-side redirect validation
    });
    
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Authentication error" });
  }
});

app.post('/api/signup', authLimiter, async (req, res) => {
  const { username, email, password: hashedPasswordHex, salt, iterations } = req.body;
  
  if (!username || !email || !hashedPasswordHex || !salt || !iterations) {
    return res.status(400).json({ error: "All fields are required" });
  }
  
  // Validate username format
  if (!/^[a-zA-Z0-9_]{4,20}$/.test(username)) {
    return res.status(400).json({ 
      field: "username", 
      error: "Only letters, numbers and underscores (4-20 characters)" 
    });
  }
  
  // Validate email format
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ 
      field: "email", 
      error: "Invalid email format" 
    });
  }
  
  // Check for existing user
  if (users.some(u => u.email === email)) {
    return res.status(400).json({ field: "email", error: "Email already in use" });
  }
  
  if (users.some(u => u.username === username)) {
    return res.status(400).json({ field: "username", error: "Username taken" });
  }
  
  // Create new user with enhanced security
  const newUser = {
    id: users.length + 1,
    username,
    email,
    password: hashedPasswordHex, // Already hashed client-side
    salt,
    iterations,
    role: "user",
    createdAt: new Date(),
    lastPasswordChange: new Date(),
    failedLoginAttempts: 0,
    accountLockedUntil: null
  };
  
  users.push(newUser);
  
  const token = jwt.sign(
    { 
      userId: newUser.id, 
      role: newUser.role,
      nonce: generateNonce()
    },
    process.env.JWT_SECRET || 'USER_SECRET_KEY',
    { expiresIn: '1h' }
  );
  
  // Set secure HTTP-only cookie
  res.cookie('oblivionToken', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000 // 1 hour
  });
  
  res.status(201).json({ 
    success: true,
    nonce: generateNonce() // For client-side redirect validation
  });
});

// Enhanced Password Reset Routes
app.post('/api/password/reset-request', authLimiter, async (req, res) => {
  const { identifier } = req.body;
  
  if (!identifier) {
    return res.status(400).json({ error: "Identifier is required" });
  }
  
  // Rate limit reset requests per identifier
  const resetAttempts = req.rateLimit.current;
  if (resetAttempts > 3) {
    return res.status(429).json({ 
      error: "Too many reset requests. Please wait before trying again." 
    });
  }
  
  const user = users.find(u => 
    u.email === identifier || u.username === identifier
  );
  
  if (!user) {
    // Don't reveal whether identifier exists
    return res.json({ 
      success: true,
      message: "If an account exists, a reset link has been sent" 
    });
  }
  
  // Generate and store token
  const token = generateToken();
  resetTokens.set(token, {
    userId: user.id,
    expires: Date.now() + 3600000, // 1 hour
    used: false
  });
  
  // Create secure reset link
  const resetLink = `${process.env.BASE_URL || 'http://localhost:3000'}/reset-password?token=${token}&nonce=${generateNonce()}`;
  
  try {
    await transporter.sendMail({
      from: `"Oblivion Security" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset for your Oblivion account.</p>
        <p>Click <a href="${resetLink}">here</a> to reset your password.</p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `,
      text: `Password reset link: ${resetLink}`
    });
  } catch (err) {
    console.error("Email error:", err);
    return res.status(500).json({ error: "Failed to send reset email" });
  }
  
  res.json({ 
    success: true,
    message: "If an account exists, a reset link has been sent" 
  });
});

app.post('/api/password/reset', authLimiter, async (req, res) => {
  const { token, newPassword: hashedPasswordHex, salt, iterations } = req.body;
  
  if (!token || !hashedPasswordHex || !salt || !iterations) {
    return res.status(400).json({ error: "All fields are required" });
  }
  
  const resetData = resetTokens.get(token);
  
  if (!resetData || resetData.expires < Date.now() || resetData.used) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }
  
  const user = users.find(u => u.id === resetData.userId);
  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }
  
  // Update user's password details
  user.password = hashedPasswordHex;
  user.salt = salt;
  user.iterations = iterations;
  user.lastPasswordChange = new Date();
  
  // Mark token as used
  resetTokens.set(token, { ...resetData, used: true });
  
  res.json({ 
    success: true,
    message: "Password updated successfully" 
  });
});

// Secure Dashboard Route
app.get('/api/dashboard', authLimiter, async (req, res) => {
  // Check for token in cookies (HTTP-only)
  const token = req.cookies.oblivionToken;
  
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'USER_SECRET_KEY');
    
    // Validate nonce if provided in query
    if (req.query.nonce && req.query.nonce !== decoded.nonce) {
      return res.status(401).json({ error: "Invalid session" });
    }
    
    // Get user data (without sensitive info)
    const user = users.find(u => u.id === decoded.userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        createdAt: user.createdAt
      }
    });
    
  } catch (err) {
    console.error("Dashboard auth error:", err);
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: "Session expired" });
    }
    
    res.status(401).json({ error: "Unauthorized" });
  }
});

// Enhanced Admin Routes
app.get('/api/admin/stats', authLimiter, async (req, res) => {
  const token = req.cookies.oblivionToken;
  
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  
  try {
    const decoded = jwt.verify(token, process.env.ADMIN_SECRET || 'ADMIN_SECRET_KEY');
    
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: "Forbidden" });
    }
    
    res.json({
      success: true,
      stats: {
        totalUsers: users.length,
        activeBots: activeBots.size,
        activeSessions: 0, // Would track active sessions in production
        systemStatus: "Operational",
        uptime: process.uptime()
      }
    });
  } catch (err) {
    console.error("Admin auth error:", err);
    res.status(401).json({ error: "Unauthorized" });
  }
});

// Logout endpoint
app.post('/api/logout', authLimiter, (req, res) => {
  // Clear the HTTP-only cookie
  res.clearCookie('oblivionToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  
  res.json({ success: true, message: "Logged out successfully" });
});

// Start server with enhanced security
const server = app.listen(PORT, () => {
  console.log(`Oblivion API running on port ${PORT}`);
  console.log(`Admin login: Username="Shadow", Password="Shadow"`);
});

// Security headers for HTTPS in production
if (process.env.NODE_ENV === 'production') {
  server.on('upgrade', (request, socket, head) => {
    socket.on('error', console.error);
  });
  
  process.on('uncaughtException', err => {
    console.error('Uncaught Exception:', err);
    process.exit(1);
  });
  
  process.on('unhandledRejection', err => {
    console.error('Unhandled Rejection:', err);
  });
}
