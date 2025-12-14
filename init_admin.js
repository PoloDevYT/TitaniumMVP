const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const db = new sqlite3.Database('./titanium.db');

const adminEmail = 'admin@titanium.com';
const adminPass = 'adminpassword';
const adminName = 'Administrator';

db.serialize(() => {
    db.run("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'", (err) => {
        if (err && !err.message.includes('duplicate column')) {
            console.error("Error adding role column:", err.message);
        } else {
            console.log("Role column ready.");
        }
    });
    const hashed = bcrypt.hashSync(adminPass, 8);

    db.get("SELECT id FROM users WHERE email = ?", [adminEmail], (err, row) => {
        if (row) {
            db.run("UPDATE users SET password = ?, role = 'admin', plan = 'black' WHERE email = ?", [hashed, adminEmail], (err) => {
                if (err) console.error(err);
                else console.log("Admin user updated.");
            });
        } else {
            db.run("INSERT INTO users (name, email, password, whatsapp, plan, role) VALUES (?, ?, ?, ?, 'black', 'admin')",
                [adminName, adminEmail, hashed, '0000000000'], (err) => {
                    if (err) console.error(err);
                    else console.log("Admin user created.");
                });
        }
    });
});
