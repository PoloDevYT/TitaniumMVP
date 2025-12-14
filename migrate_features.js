const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./titanium.db');

db.serialize(() => {
    // 1. Progress Entries
    db.run(`CREATE TABLE IF NOT EXISTS progress_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        weight_kg REAL,
        body_fat REAL,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, (err) => {
        if (err) console.error(err);
        else console.log("progress_entries ready.");
    });

    // 2. Community Posts
    db.run(`CREATE TABLE IF NOT EXISTS community_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, (err) => {
        if (err) console.error(err);
        else console.log("community_posts ready.");
    });
});

db.close();
console.log("All tables created.");
