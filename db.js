const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'goaltracker.db');

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database ' + dbPath + ': ' + err.message);
    } else {
        console.log('Connected to the SQLite database.');
        initDb();
    }
});

function initDb() {
    db.serialize(() => {
        // Users table
        db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      google_id TEXT UNIQUE,
      phone TEXT UNIQUE,
      otp_code TEXT,
      otp_expiry DATETIME,
      reset_token TEXT,
      reset_token_expiry DATETIME
    )`);

        // Daily Logs table
        db.run(`CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      date TEXT,
      topic TEXT,
      hours REAL,
      status TEXT,
      notes TEXT
    )`);

        // Todos table
        db.run(`CREATE TABLE IF NOT EXISTS todos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task TEXT,
      details TEXT,
      format TEXT,
      section TEXT,
      is_completed INTEGER DEFAULT 0,
      source TEXT
    )`);

        // Migrations for existing tables
        db.run("ALTER TABLE todos ADD COLUMN details TEXT", (err) => {
            if (err && !err.message.includes('duplicate column')) {
                // Ignore error if column already exists
            }
        });
        db.run("ALTER TABLE todos ADD COLUMN format TEXT", (err) => {
            if (err && !err.message.includes('duplicate column')) {
                // Ignore error if column already exists
            }
        });
        db.run("ALTER TABLE todos ADD COLUMN section TEXT", (err) => {
            if (err && !err.message.includes('duplicate column')) {
                // Ignore error if column already exists
            }
        });
        db.run("ALTER TABLE todos ADD COLUMN completed_at TEXT", (err) => {
            if (err && !err.message.includes('duplicate column')) {
                // Ignore error if column already exists
            }
        });
        db.run("ALTER TABLE todos ADD COLUMN created_at TEXT", (err) => {
            if (err && !err.message.includes('duplicate column')) {
                // Ignore error if column already exists
            }
        });
        db.run("ALTER TABLE todos ADD COLUMN priority TEXT DEFAULT 'Medium'", (err) => {
            if (err && !err.message.includes('duplicate column')) {
                // Ignore error if column already exists
            }
        });
        db.run("ALTER TABLE todos ADD COLUMN due_date TEXT", (err) => {
            if (err && !err.message.includes('duplicate column')) {
                // Ignore error if column already exists
            }
        });
        db.run("ALTER TABLE logs ADD COLUMN created_at TEXT", (err) => {
            if (err && !err.message.includes('duplicate column')) {
                // Ignore error if column already exists
            }
        });
        db.run("ALTER TABLE logs ADD COLUMN events TEXT", (err) => {
            if (err && !err.message.includes('duplicate column')) {
                // Ignore error if column already exists
            }
        });
        db.run("ALTER TABLE logs ADD COLUMN user_id INTEGER", (err) => {
            if (err && !err.message.includes('duplicate column')) {
                // Ignore error if column already exists
            }
        });
        db.run("ALTER TABLE todos ADD COLUMN user_id INTEGER", (err) => {
            if (err && !err.message.includes('duplicate column')) {
                // Ignore error if column already exists
            }
        });

        // Ensure Default Global Operator exists
        db.run(`INSERT OR IGNORE INTO users (id, username) VALUES (1, 'Global Operator')`);
    });
}

module.exports = db;
