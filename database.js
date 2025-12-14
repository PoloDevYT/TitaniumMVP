const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Connect to SQLite database (creates file if not exists)
const dbPath = path.resolve(__dirname, 'titanium.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to the Titanium SQLite database.');
    }
});

// Create Users Table
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        whatsapp TEXT,
        plan TEXT DEFAULT 'free', -- free, iron, black
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS user_stats (
        user_id INTEGER PRIMARY KEY,
        streak_days INTEGER DEFAULT 0,
        total_load_kg INTEGER DEFAULT 0,
        last_checkin DATETIME,
        monthly_checkins INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
});

module.exports = db;
