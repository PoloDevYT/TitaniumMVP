const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./titanium.db');

db.serialize(() => {
    // User custom workouts
    db.run(`CREATE TABLE IF NOT EXISTS user_workouts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        exercises TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, (err) => {
        if (err) console.error("Error:", err);
        else console.log("user_workouts table ready.");
    });
});

db.close();
