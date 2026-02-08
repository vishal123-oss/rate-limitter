const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const USERS_FILE = path.join(process.env.DATA_DIR || './data', 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-prod';
const SALT_ROUNDS = 10;

// Limited server roles (enforced on signup)
const ALLOWED_ROLES = ['user', 'admin'];

class AuthService {
  constructor() {
    this.ensureUsersFile();
  }

  ensureUsersFile() {
    if (!fs.existsSync(USERS_FILE)) {
      fs.writeFileSync(USERS_FILE, JSON.stringify([]));
    }
  }

  getUsers() {
    try {
      return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    } catch (err) {
      return [];
    }
  }

  saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  }

  async register(username, password, role = 'user') {
    const users = this.getUsers();
    if (users.find(u => u.username === username)) {
      throw new Error('User already exists');
    }
    if (!ALLOWED_ROLES.includes(role)) {
      throw new Error('assigned role does not exist Please contact admin');
    }
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const user = { id: Date.now().toString(), username, password: hashedPassword, role };
    users.push(user);
    this.saveUsers(users);
    return { id: user.id, username: user.username, role: user.role };
  }

  async login(username, password) {
    const users = this.getUsers();
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new Error('Invalid credentials');
    }
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    return { token, user: { id: user.id, username: user.username, role: user.role } };
  }

  verifyToken(token) {
    try {
      return jwt.verify(token, JWT_SECRET);
    } catch (err) {
      throw new Error('Invalid token');
    }
  }
}

module.exports = new AuthService();
