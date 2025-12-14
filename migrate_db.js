const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./titanium.db');

db.serialize(() => {
    // Add 'plan' column to users table
    db.run("ALTER TABLE users ADD COLUMN plan TEXT DEFAULT 'free'", (err) => {
        if (err) {
            if (err.message.includes('duplicate column name')) {
                console.log("Column 'plan' already exists.");
            } else {
                console.error("Error adding 'plan' column:", err.message);
            }
        } else {
            console.log("Column 'plan' added successfully.");
        }
    });
});

db.close();
