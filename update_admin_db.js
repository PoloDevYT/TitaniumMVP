const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./titanium.db');

db.serialize(() => {
    // 1. Logs Table
    db.run(`CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, (err) => {
        if (err) console.error("Error creating logs table:", err);
        else console.log("Logs table ready.");
    });

    // 2. Settings Table
    db.run(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )`, (err) => {
        if (err) console.error("Error creating settings table:", err);
        else {
            console.log("Settings table ready.");
            // Seed defaults
            db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES 
                ('maintenance_mode', 'false'),
                ('global_announcement', '')
            `);
        }
    });
});

db.close();
