const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const db = new Database('users.db');
const JWT_SECRET = 'super-secret-jwt-key-2024';
const ADMIN_EMAIL = 'raffaka16k@gmail.com';

// Init DB
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    plain_password TEXT,
    full_name TEXT,
    phone TEXT,
    bio TEXT,
    avatar_color TEXT DEFAULT '#6c63ff',
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
  )
`);

// Add plain_password column if upgrading from old DB
try { db.exec('ALTER TABLE users ADD COLUMN plain_password TEXT'); } catch {}

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Не авторизован' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Токен недействителен' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Только для администратора' });
  next();
}

// Register
app.post('/api/register', async (req, res) => {
  const { username, email, password, full_name, phone } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Заполните все обязательные поля' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });

  const hash = bcrypt.hashSync(password, 10);
  const role = email === ADMIN_EMAIL ? 'admin' : 'user';
  const colors = ['#6c63ff', '#ff6584', '#43b89c', '#f7b731', '#e056fd', '#26de81'];
  const avatar_color = colors[Math.floor(Math.random() * colors.length)];

  try {
    const stmt = db.prepare('INSERT INTO users (username, email, password, plain_password, full_name, phone, role, avatar_color) VALUES (?,?,?,?,?,?,?,?)');
    const result = stmt.run(username, email, hash, password, full_name || '', phone || '', role, avatar_color);
    const token = jwt.sign({ id: result.lastInsertRowid, username, email, role }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ success: true, role, username });
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      if (e.message.includes('username')) return res.status(400).json({ error: 'Это имя пользователя уже занято' });
      if (e.message.includes('email')) return res.status(400).json({ error: 'Этот email уже зарегистрирован' });
    }
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Неверный email или пароль' });
  }
  db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  const token = jwt.sign({ id: user.id, username: user.username, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
  res.json({ success: true, role: user.role, username: user.username });
});

// Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// Get own profile
app.get('/api/profile', auth, (req, res) => {
  const user = db.prepare('SELECT id, username, email, full_name, phone, bio, avatar_color, role, created_at, last_login FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

// Update own profile
app.put('/api/profile', auth, (req, res) => {
  const { full_name, phone, bio } = req.body;
  db.prepare('UPDATE users SET full_name=?, phone=?, bio=? WHERE id=?').run(full_name || '', phone || '', bio || '', req.user.id);
  res.json({ success: true });
});

// Admin: get all users
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = db.prepare('SELECT id, username, email, plain_password, full_name, phone, bio, avatar_color, role, created_at, last_login FROM users ORDER BY created_at DESC').all();
  res.json(users);
});

// Admin: get single user
app.get('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const user = db.prepare('SELECT id, username, email, plain_password, full_name, phone, bio, avatar_color, role, created_at, last_login FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json(user);
});

// Admin: delete user
app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  if (user.email === ADMIN_EMAIL) return res.status(403).json({ error: 'Нельзя удалить администратора' });
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Admin: update user role
app.put('/api/admin/users/:id/role', auth, adminOnly, (req, res) => {
  const { role } = req.body;
  if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'Неверная роль' });
  db.prepare('UPDATE users SET role=? WHERE id=?').run(role, req.params.id);
  res.json({ success: true });
});

// Admin stats
app.get('/api/admin/stats', auth, adminOnly, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  const admins = db.prepare("SELECT COUNT(*) as count FROM users WHERE role='admin'").get().count;
  const today = db.prepare("SELECT COUNT(*) as count FROM users WHERE date(created_at) = date('now')").get().count;
  res.json({ total, admins, today });
});

app.listen(3000, () => console.log('Сервер запущен: http://localhost:3000'));
