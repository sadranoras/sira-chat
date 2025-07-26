import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

export async function connectToDb() {
  const db = await open({
    filename: './database.sqlite',
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'user'
    );
    
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER,
      receiver_id INTEGER,
      content TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(sender_id) REFERENCES users(id),
      FOREIGN KEY(receiver_id) REFERENCES users(id)
    );
  `);

  const adminExists = await db.get(`SELECT * FROM users WHERE username = 'admin'`);
  if (!adminExists) {
    const bcrypt = await import('bcrypt');
    const hash = await bcrypt.hash('123456', 10);
    await db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, ['admin', hash, 'admin']);
  }

  return db;
}
