// server.js
import express from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs'; // تغییر داده شده از bcrypt به bcryptjs
import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const sqlite = sqlite3.verbose();
const db = new sqlite.Database('./chat.db');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'supersecretkey',
  resave: false,
  saveUninitialized: false,
}));

app.use(express.static(path.join(__dirname, 'public')));

// ساخت جداول اگر وجود ندارند
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    sender TEXT,
    receiver_id INTEGER,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(receiver_id) REFERENCES users(id)
  )`);

  // ساخت ادمین اولیه در صورت نبود
  db.get("SELECT * FROM users WHERE role='admin'", (err, row) => {
    if (!row) {
      const hashed = bcrypt.hashSync('admin123', 10);
      db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')`, ['admin', hashed]);
      console.log('ادمین نمونه ساخته شد: username=admin, password=admin123');
    }
  });
});

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).send('لطفا وارد شوید');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).send('دسترسی غیرمجاز');
  next();
}

// ثبت‌نام
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('نام کاربری و رمز عبور الزامی است');

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(400).send('نام کاربری قبلا استفاده شده');
        return res.status(500).send('خطای سرور');
      }
      res.send('ثبت‌نام با موفقیت انجام شد');
    });
  } catch (error) {
    res.status(500).send('خطای سرور');
  }
});

// ورود
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('نام کاربری و رمز عبور الزامی است');

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).send('خطای سرور');
    if (!user) return res.status(400).send('نام کاربری یا رمز عبور اشتباه است');

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).send('نام کاربری یا رمز عبور اشتباه است');

    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.send('ورود موفق');
  });
});

// خروج
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

// پروفایل
app.get('/profile', requireLogin, (req, res) => {
  res.json(req.session.user);
});

// لیست کاربران
app.get('/users', requireLogin, (req, res) => {
  db.all('SELECT id, username, role FROM users', (err, rows) => {
    if (err) return res.status(500).send('خطا در دریافت کاربران');
    res.json(rows);
  });
});

// دریافت پیام‌ها
app.get('/messages', requireLogin, (req, res) => {
  const userId = req.session.user.id;
  const sql = `
    SELECT * FROM messages
    WHERE receiver_id IS NULL
    OR sender_id = ?
    OR receiver_id = ?
    ORDER BY created_at ASC
  `;
  db.all(sql, [userId, userId], (err, rows) => {
    if (err) return res.status(500).send('خطا در دریافت پیام‌ها');
    res.json(rows);
  });
});

// ارسال پیام
app.post('/message', requireLogin, (req, res) => {
  const sender_id = req.session.user.id;
  const sender = req.session.user.username;
  const { content, receiverId } = req.body;

  if (!content || content.trim() === '') return res.status(400).send('پیام نمی‌تواند خالی باشد');

  const sql = 'INSERT INTO messages (sender_id, sender, receiver_id, content) VALUES (?, ?, ?, ?)';
  db.run(sql, [sender_id, sender, receiverId || null, content], function(err) {
    if (err) return res.status(500).send('خطا در ارسال پیام');
    res.send('پیام ارسال شد');
  });
});

// حذف پیام (ادمین)
app.delete('/message/:id', requireLogin, requireAdmin, (req, res) => {
  const messageId = req.params.id;
  db.get('SELECT * FROM messages WHERE id = ?', [messageId], (err, row) => {
    if (err) return res.status(500).send('خطا در سرور');
    if (!row) return res.status(404).send('پیام پیدا نشد');

    db.run('DELETE FROM messages WHERE id = ?', [messageId], function(err2) {
      if (err2) return res.status(500).send('خطا در حذف پیام');
      if (this.changes === 0) return res.status(404).send('پیام حذف نشد');
      res.send('پیام حذف شد');
    });
  });
});

// تغییر رمز عبور
app.post('/change-password', requireLogin, async (req, res) => {
  const userId = req.session.user.id;
  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) return res.status(400).send('رمزهای عبور باید وارد شوند');

  db.get('SELECT password FROM users WHERE id = ?', [userId], async (err, row) => {
    if (err) return res.status(500).send('خطا در سرور');
    if (!row) return res.status(404).send('کاربر یافت نشد');

    const match = await bcrypt.compare(oldPassword, row.password);
    if (!match) return res.status(400).send('رمز عبور فعلی اشتباه است');

    const hashed = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, userId], function(err2) {
      if (err2) return res.status(500).send('خطا در به‌روزرسانی رمز عبور');
      res.send('رمز عبور با موفقیت تغییر کرد');
    });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});


