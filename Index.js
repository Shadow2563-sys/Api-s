// admin-api.js
require('dotenv').config();
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

// Mock database (replace with real DB in production)
let users = [
  {
    id: 1,
    username: "Shadow",
    email: "admin@oblivion.com",
    password: "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW", // "Shadow"
    salt: "randomSalt123",
    iterations: 100000,
    role: "admin",
    joinedAt: new Date(),
    lastActive: new Date(),
    banned: false,
    botsDeployed: 5
  }
];

let botDeployments = [
  {
    id: "bot-001",
    userId: 1,
    username: "Shadow",
    phoneNumber: "+1234567890",
    status: "active",
    startedAt: new Date(Date.now() - 3600000),
    lastActive: new Date(),
    commandsExecuted: 42,
    ipAddress: "192.168.1.100"
  }
];

let userActivity = [];
let apiUsageData = {
  totalRequests: 0,
  endpoints: []
};

// Admin rate limiting
const adminLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // limit each IP to 30 requests per minute
  message: "Too many requests from this IP, please try again later"
});

// Verify Admin Token Middleware
function verifyAdminToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(403).json({ error: "No token provided" });
  }

  jwt.verify(token, process.env.ADMIN_SECRET || 'ADMIN_SECRET_KEY', (err, decoded) => {
    if (err || decoded.role !== 'admin') {
      return res.status(401).json({ error: "Unauthorized" });
    }
    
    req.userId = decoded.userId;
    next();
  });
}

// Generate mock data for dashboard
function generateMockData() {
  // Generate user activity
  userActivity = [];
  const actions = ["login", "logout", "bot_start", "bot_stop", "api_call", "password_change"];
  const statuses = ["success", "failed", "pending"];
  
  for (let i = 0; i < 50; i++) {
    const randomUser = users[Math.floor(Math.random() * users.length)];
    const randomAction = actions[Math.floor(Math.random() * actions.length)];
    const randomStatus = statuses[Math.floor(Math.random() * statuses.length)];
    
    userActivity.push({
      id: `act-${i}`,
      userId: randomUser.id,
      username: randomUser.username,
      action: randomAction,
      status: randomStatus,
      timestamp: new Date(Date.now() - Math.floor(Math.random() * 7 * 24 * 3600000)),
      ipAddress: `192.168.1.${Math.floor(Math.random() * 255)}`,
      details: `${randomAction} ${randomStatus}`
    });
  }

  // Generate API usage data
  apiUsageData = {
    totalRequests: 12456,
    labels: Array.from({length: 24}, (_, i) => `${i}:00`),
    data: Array.from({length: 24}, () => Math.floor(Math.random() * 1000)),
    endpoints: [
      { path: "/api/login", requests24h: 3421, successRate: 98, avgResponseTime: 120, errors: 12 },
      { path: "/api/bot/start", requests24h: 1567, successRate: 95, avgResponseTime: 250, errors: 23 },
      { path: "/api/bot/stop", requests24h: 892, successRate: 97, avgResponseTime: 180, errors: 8 },
      { path: "/api/admin/stats", requests24h: 432, successRate: 99, avgResponseTime: 80, errors: 1 }
    ]
  };
}

// Initialize mock data
generateMockData();

// Admin Dashboard Endpoint
router.get('/dashboard', verifyAdminToken, adminLimiter, (req, res) => {
  const stats = {
    totalUsers: users.length,
    activeBots: botDeployments.filter(b => b.status === 'active').length,
    totalRequests: apiUsageData.totalRequests,
    totalCommands: botDeployments.reduce((sum, bot) => sum + bot.commandsExecuted, 0),
    serverNodes: 3, // Assuming 3 server nodes
    systemStatus: "Operational",
    uptime: process.uptime(),
    recentActivity: userActivity.slice(0, 10).sort((a, b) => b.timestamp - a.timestamp),
    users: users.map(user => ({
      ...user,
      password: undefined,
      salt: undefined
    })),
    botDeployments,
    userActivity: userActivity.sort((a, b) => b.timestamp - a.timestamp),
    apiUsage: {
      labels: apiUsageData.labels,
      data: apiUsageData.data,
      endpoints: apiUsageData.endpoints
    }
  };

  res.json(stats);
});

// Bot Management Endpoints
router.post('/bots/:id/stop', verifyAdminToken, adminLimiter, (req, res) => {
  const bot = botDeployments.find(b => b.id === req.params.id);
  if (!bot) {
    return res.status(404).json({ error: "Bot not found" });
  }

  bot.status = "stopped";
  bot.lastActive = new Date();
  
  userActivity.push({
    userId: req.userId,
    username: "Admin",
    action: "bot_stop",
    status: "success",
    timestamp: new Date(),
    ipAddress: req.ip,
    details: `Stopped bot ${req.params.id}`
  });

  res.json({ success: true, message: "Bot stopped successfully" });
});

router.post('/bots/:id/restart', verifyAdminToken, adminLimiter, (req, res) => {
  const bot = botDeployments.find(b => b.id === req.params.id);
  if (!bot) {
    return res.status(404).json({ error: "Bot not found" });
  }

  bot.status = "active";
  bot.lastActive = new Date();
  
  userActivity.push({
    userId: req.userId,
    username: "Admin",
    action: "bot_restart",
    status: "success",
    timestamp: new Date(),
    ipAddress: req.ip,
    details: `Restarted bot ${req.params.id}`
  });

  res.json({ success: true, message: "Bot restarted successfully" });
});

// User Management Endpoints
router.post('/users/:id/ban', verifyAdminToken, adminLimiter, (req, res) => {
  const user = users.find(u => u.id == req.params.id);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  if (user.role === 'admin') {
    return res.status(403).json({ error: "Cannot ban admin users" });
  }

  user.banned = true;
  
  userActivity.push({
    userId: req.userId,
    username: "Admin",
    action: "user_ban",
    status: "success",
    timestamp: new Date(),
    ipAddress: req.ip,
    details: `Banned user ${user.username}`
  });

  res.json({ success: true, message: "User banned successfully" });
});

router.post('/users/:id/unban', verifyAdminToken, adminLimiter, (req, res) => {
  const user = users.find(u => u.id == req.params.id);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  user.banned = false;
  
  userActivity.push({
    userId: req.userId,
    username: "Admin",
    action: "user_unban",
    status: "success",
    timestamp: new Date(),
    ipAddress: req.ip,
    details: `Unbanned user ${user.username}`
  });

  res.json({ success: true, message: "User unbanned successfully" });
});

// System Logs Endpoint
router.get('/logs', verifyAdminToken, adminLimiter, (req, res) => {
  try {
    // In production, you'd want to read from actual log files
    const logs = [
      { timestamp: new Date(), level: "INFO", message: "System startup completed" },
      { timestamp: new Date(Date.now() - 10000), level: "DEBUG", message: "Processing bot deployment request" },
      { timestamp: new Date(Date.now() - 30000), level: "WARN", message: "High CPU usage detected on node 2" }
    ];
    
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: "Error reading logs" });
  }
});

// Export bot deployment data
router.get('/bots/export', verifyAdminToken, adminLimiter, (req, res) => {
  try {
    const data = {
      timestamp: new Date(),
      botDeployments,
      generatedBy: `Admin user ${req.userId}`
    };
    
    const filePath = path.join(__dirname, 'exports', `bot-export-${Date.now()}.json`);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    
    res.download(filePath, () => {
      // Delete the file after download completes
      setTimeout(() => fs.unlinkSync(filePath), 5000);
    });
  } catch (error) {
    res.status(500).json({ error: "Error generating export" });
  }
});

// API Usage Statistics
router.get('/api/stats', verifyAdminToken, adminLimiter, (req, res) => {
  res.json({
    totalRequests: apiUsageData.totalRequests,
    endpoints: apiUsageData.endpoints,
    hourlyUsage: {
      labels: apiUsageData.labels,
      data: apiUsageData.data
    }
  });
});

module.exports = router;
