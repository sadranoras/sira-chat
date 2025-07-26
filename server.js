// server.js (با PostgreSQL)
import express from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // لینک PostgreSQL از Render
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'supersecretkey',
  resave: false,
  saveUninitialized: false,
}));

app.use(express.static(path.join(__dirname, 'public')));

// ساخت جداول در صورت نیاز
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'user'
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER REFERENCES users(id),
      sender TEXT,
      receiver_id INTEGER REFERENCES users(id),
      content TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const { rows } = await pool.query("SELECT * FROM users WHERE role='admin'");
  if (rows.length === 0) {
    const hashed = await bcrypt.hash('admin123', 10);
    await pool.query(
      "INSERT INTO users (username, password, role) VALUES ($1, $2, 'admin')",
      ['admin', hashed]
    );
    console.log('ادمین نمونه ساخته شد: username=admin, password=admin123');
  }
}

initDB();

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).send('لطفا وارد شوید');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).send('دسترسی غیرمجاز');
  next();
}

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('نام کاربری و رمز عبور الزامی است');
  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashed]);
    res.send('ثبت‌نام با موفقیت انجام شد');
  } catch (err) {
    if (err.code === '23505') return res.status(400).send('نام کاربری قبلا استفاده شده');
    res.status(500).send('خطای سرور');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('نام کاربری و رمز عبور الزامی است');
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(400).send('نام کاربری یا رمز عبور اشتباه است');
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).send('نام کاربری یا رمز عبور اشتباه است');
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.send('ورود موفق');
  } catch (err) {
    res.status(500).send('خطای سرور');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

app.get('/profile', requireLogin, (req, res) => {
  res.json(req.session.user);
});

app.get('/users', requireLogin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, role FROM users');
    res.json(result.rows);
  } catch {
    res.status(500).send('خطا در دریافت کاربران');
  }
});

app.get('/messages', requireLogin, async (req, res) => {
  const userId = req.session.user.id;
  try {
    const result = await pool.query(
      `SELECT * FROM messages
       WHERE receiver_id IS NULL OR sender_id = $1 OR receiver_id = $1
       ORDER BY created_at ASC`,
      [userId]
    );
    res.json(result.rows);
  } catch {
    res.status(500).send('خطا در دریافت پیام‌ها');
  }
});

app.post('/message', requireLogin, async (req, res) => {
  const sender_id = req.session.user.id;
  const sender = req.session.user.username;
  const { content, receiverId } = req.body;
  if (!content || content.trim() === '') return res.status(400).send('پیام نمی‌تواند خالی باشد');
  try {
    await pool.query(
      'INSERT INTO messages (sender_id, sender, receiver_id, content) VALUES ($1, $2, $3, $4)',
      [sender_id, sender, receiverId || null, content]
    );
    res.send('پیام ارسال شد');
  } catch {
    res.status(500).send('خطا در ارسال پیام');
  }
});

app.delete('/message/:id', requireLogin, requireAdmin, async (req, res) => {
  const messageId = req.params.id;
  try {
    const result = await pool.query('DELETE FROM messages WHERE id = $1', [messageId]);
    if (result.rowCount === 0) return res.status(404).send('پیام حذف نشد');
    res.send('پیام حذف شد');
  } catch {
    res.status(500).send('خطا در حذف پیام');
  }
});

app.post('/change-password', requireLogin, async (req, res) => {
  const userId = req.session.user.id;
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return res.status(400).send('رمزهای عبور باید وارد شوند');
  try {
    const result = await pool.query('SELECT password FROM users WHERE id = $1', [userId]);
    const user = result.rows[0];
    if (!user) return res.status(404).send('کاربر یافت نشد');
    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) return res.status(400).send('رمز عبور فعلی اشتباه است');
    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashed, userId]);
    res.send('رمز عبور با موفقیت تغییر کرد');
  } catch {
    res.status(500).send('خطا در به‌روزرسانی رمز عبور');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
