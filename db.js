const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

class Database {
  constructor() {
    this.db = new sqlite3.Database('./database.sqlite');
    this.init();
  }

  init() {
    // Create uploads directory
    if (!fs.existsSync('./uploads')) {
      fs.mkdirSync('./uploads');
    }

    // Create tables
    this.db.serialize(() => {
      // Users table
      this.db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          role TEXT DEFAULT 'user',
          verified INTEGER DEFAULT 0,
          reset_token TEXT,
          reset_expires INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Messages table
      this.db.run(`
        CREATE TABLE IF NOT EXISTS messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          username TEXT,
          message TEXT NOT NULL,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users (id)
        )
      `);

      // Files table
      this.db.run(`
        CREATE TABLE IF NOT EXISTS files (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          filename TEXT NOT NULL,
          original_name TEXT NOT NULL,
          filesize INTEGER NOT NULL,
          visibility TEXT DEFAULT 'private',
          upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users (id)
        )
      `);

      // Verification tokens table
      this.db.run(`
        CREATE TABLE IF NOT EXISTS verification_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          token TEXT UNIQUE NOT NULL,
          expires INTEGER NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users (id)
        )
      `);
    });
  }

  // User methods
  createUser(username, email, password, callback) {
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    // Check if this is the first user (make admin)
    this.db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
      if (err) return callback(err);
      
      const role = row.count === 0 ? 'admin' : 'user';
      
      this.db.run(
        'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
        [username, email, hashedPassword, role],
        function(err) {
          if (err) return callback(err);
          callback(null, { id: this.lastID, role });
        }
      );
    });
  }

  getUserByEmail(email, callback) {
    this.db.get('SELECT * FROM users WHERE email = ?', [email], callback);
  }

  getUserByUsername(username, callback) {
    this.db.get('SELECT * FROM users WHERE username = ?', [username], callback);
  }

  getUserById(id, callback) {
    this.db.get('SELECT * FROM users WHERE id = ?', [id], callback);
  }

  verifyUser(userId, callback) {
    this.db.run('UPDATE users SET verified = 1 WHERE id = ?', [userId], callback);
  }

  updateUserPassword(userId, newPassword, callback) {
    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    this.db.run('UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?', 
      [hashedPassword, userId], callback);
  }

  setResetToken(userId, token, expires, callback) {
    this.db.run('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?', 
      [token, expires, userId], callback);
  }

  getUserByResetToken(token, callback) {
    const now = Date.now();
    this.db.get('SELECT * FROM users WHERE reset_token = ? AND reset_expires > ?', 
      [token, now], callback);
  }

  // Verification token methods
  createVerificationToken(userId, token, expires, callback) {
    this.db.run('INSERT INTO verification_tokens (user_id, token, expires) VALUES (?, ?, ?)',
      [userId, token, expires], callback);
  }

  getVerificationToken(token, callback) {
    const now = Date.now();
    this.db.get('SELECT * FROM verification_tokens WHERE token = ? AND expires > ?', 
      [token, now], callback);
  }

  deleteVerificationToken(token, callback) {
    this.db.run('DELETE FROM verification_tokens WHERE token = ?', [token], callback);
  }

  // Message methods
  addMessage(userId, username, message, callback) {
    this.db.run('INSERT INTO messages (user_id, username, message) VALUES (?, ?, ?)',
      [userId, username, message], callback);
  }

  getRecentMessages(limit = 50, callback) {
    this.db.all('SELECT * FROM messages ORDER BY timestamp DESC LIMIT ?', [limit], 
      (err, rows) => {
        if (err) return callback(err);
        callback(null, rows.reverse());
      });
  }

  deleteMessage(messageId, callback) {
    this.db.run('DELETE FROM messages WHERE id = ?', [messageId], callback);
  }

  // File methods
  addFile(userId, filename, originalName, filesize, visibility, callback) {
    this.db.run('INSERT INTO files (user_id, filename, original_name, filesize, visibility) VALUES (?, ?, ?, ?, ?)',
      [userId, filename, originalName, filesize, visibility], function(err) {
        if (err) return callback(err);
        callback(null, this.lastID);
      });
  }

  getUserFiles(userId, callback) {
    this.db.all('SELECT * FROM files WHERE user_id = ? ORDER BY upload_date DESC', 
      [userId], callback);
  }

  getPublicFiles(callback) {
    this.db.all(`
      SELECT f.*, u.username 
      FROM files f 
      JOIN users u ON f.user_id = u.id 
      WHERE f.visibility = 'public' 
      ORDER BY f.upload_date DESC
    `, callback);
  }

  getAllFiles(callback) {
    this.db.all(`
      SELECT f.*, u.username 
      FROM files f 
      JOIN users u ON f.user_id = u.id 
      ORDER BY f.upload_date DESC
    `, callback);
  }

  deleteFile(fileId, callback) {
    this.db.get('SELECT * FROM files WHERE id = ?', [fileId], (err, file) => {
      if (err) return callback(err);
      if (!file) return callback(new Error('File not found'));
      
      this.db.run('DELETE FROM files WHERE id = ?', [fileId], (err) => {
        if (err) return callback(err);
        callback(null, file);
      });
    });
  }

  getUserStorageUsed(userId, callback) {
    this.db.get('SELECT COALESCE(SUM(filesize), 0) as total FROM files WHERE user_id = ?', 
      [userId], callback);
  }

  // Admin methods
  getAllUsers(callback) {
    this.db.all('SELECT id, username, email, role, verified, created_at FROM users ORDER BY created_at DESC', 
      callback);
  }

  updateUserRole(userId, role, callback) {
    this.db.run('UPDATE users SET role = ? WHERE id = ?', [role, userId], callback);
  }

  deleteUser(userId, callback) {
    this.db.serialize(() => {
      this.db.run('DELETE FROM messages WHERE user_id = ?', [userId]);
      this.db.run('DELETE FROM files WHERE user_id = ?', [userId]);
      this.db.run('DELETE FROM verification_tokens WHERE user_id = ?', [userId]);
      this.db.run('DELETE FROM users WHERE id = ?', [userId], callback);
    });
  }

  getAllMessages(callback) {
    this.db.all(`
      SELECT m.*, u.username 
      FROM messages m 
      JOIN users u ON m.user_id = u.id 
      ORDER BY m.timestamp DESC
    `, callback);
  }
}

module.exports = new Database();