const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-2024';
const ADMIN_EMAIL = 'raffaka16k@gmail.com';

// Init DB
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      plain_password TEXT,
      full_name TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      bio TEXT DEFAULT '',
      avatar_color TEXT DEFAULT '#6c63ff',
      role TEXT DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_login TIMESTAMPTZ
    )
  `);
}
initDB().catch(console.error);

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
    const result = await pool.query(
      'INSERT INTO users (username, email, password, plain_password, full_name, phone, role, avatar_color) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id',
      [username, email, hash, password, full_name || '', phone || '', role, avatar_color]
    );
    const token = jwt.sign({ id: result.rows[0].id, username, email, role }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ success: true, role, username });
  } catch (e) {
    if (e.code === '23505') {
      if (e.constraint?.includes('username')) return res.status(400).json({ error: 'Это имя пользователя уже занято' });
      if (e.constraint?.includes('email')) return res.status(400).json({ error: 'Этот email уже зарегистрирован' });
    }
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = rows[0];
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Неверный email или пароль' });
  }
  await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
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
app.get('/api/profile', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, username, email, full_name, phone, bio, avatar_color, role, created_at, last_login FROM users WHERE id = $1',
    [req.user.id]
  );
  res.json(rows[0]);
});

// Update own profile
app.put('/api/profile', auth, async (req, res) => {
  const { full_name, phone, bio } = req.body;
  await pool.query('UPDATE users SET full_name=$1, phone=$2, bio=$3 WHERE id=$4', [full_name || '', phone || '', bio || '', req.user.id]);
  res.json({ success: true });
});

// Admin: get all users
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, username, email, plain_password, full_name, phone, bio, avatar_color, role, created_at, last_login FROM users ORDER BY created_at DESC'
  );
  res.json(rows);
});

// Admin: get single user
app.get('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, username, email, plain_password, full_name, phone, bio, avatar_color, role, created_at, last_login FROM users WHERE id = $1',
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json(rows[0]);
});

// Admin: delete user
app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Пользователь не найден' });
  if (rows[0].email === ADMIN_EMAIL) return res.status(403).json({ error: 'Нельзя удалить администратора' });
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// Admin: update user role
app.put('/api/admin/users/:id/role', auth, adminOnly, async (req, res) => {
  const { role } = req.body;
  if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'Неверная роль' });
  await pool.query('UPDATE users SET role=$1 WHERE id=$2', [role, req.params.id]);
  res.json({ success: true });
});

// Admin stats
app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  const total = (await pool.query('SELECT COUNT(*) FROM users')).rows[0].count;
  const admins = (await pool.query("SELECT COUNT(*) FROM users WHERE role='admin'")).rows[0].count;
  const today = (await pool.query("SELECT COUNT(*) FROM users WHERE created_at::date = CURRENT_DATE")).rows[0].count;
  res.json({ total: +total, admins: +admins, today: +today });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен: http://localhost:${PORT}`));
