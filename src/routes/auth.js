const express = require('express');
const authService = require('../services/AuthService');
const suspiciousService = require('../services/SuspiciousActivityService');

const router = express.Router();

router.post('/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    const user = await authService.register(username, password, role);
    res.status(201).json({ message: 'User registered', user });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    const result = await authService.login(username, password);
    res.json({ message: 'Login successful', ...result });
  } catch (err) {
    // Track login failure for suspicious/block (IP-based, normalize localhost)
    let ip = req.ip || req.connection.remoteAddress;
    ip = suspiciousService.normalizeIP ? suspiciousService.normalizeIP(ip) : ip;
    suspiciousService.trackFailure(ip);
    res.status(401).json({ error: err.message });
  }
});

module.exports = router;
