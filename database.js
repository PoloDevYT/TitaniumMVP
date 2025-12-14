const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'titanium.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to the Titanium SQLite database.');
    }
});

function runAsync(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) return reject(err);
            resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

function getAsync(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
    });
}

function allAsync(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
    });
}

async function ensureColumn(table, column, definition) {
    const info = await allAsync(`PRAGMA table_info(${table})`);
    const exists = info.some((c) => c.name === column);
    if (!exists) {
        await runAsync(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
        console.log(`Added missing column ${column} to ${table}.`);
    }
}

async function ensureSetting(key, value) {
    const row = await getAsync('SELECT value FROM settings WHERE key = ?', [key]);
    if (!row) {
        await runAsync('INSERT INTO settings (key, value) VALUES (?, ?)', [key, value]);
    }
}

async function initializeSchema() {
    await runAsync(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        whatsapp TEXT,
        plan TEXT DEFAULT 'free',
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    await runAsync('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)');

    await ensureColumn('users', 'plan', "TEXT DEFAULT 'free'");
    await ensureColumn('users', 'role', "TEXT DEFAULT 'user'");
    await ensureColumn('users', 'whatsapp', 'TEXT');

    await runAsync(`CREATE TABLE IF NOT EXISTS user_stats (
        user_id INTEGER PRIMARY KEY,
        streak_days INTEGER DEFAULT 0,
        total_load_kg INTEGER DEFAULT 0,
        last_checkin DATETIME,
        monthly_checkins INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    await runAsync(`CREATE TABLE IF NOT EXISTS workouts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        level TEXT,
        focus TEXT,
        duration_minutes INTEGER,
        equipment TEXT,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    await ensureColumn('workouts', 'level', 'TEXT');
    await ensureColumn('workouts', 'focus', 'TEXT');
    await ensureColumn('workouts', 'duration_minutes', 'INTEGER');
    await ensureColumn('workouts', 'equipment', 'TEXT');
    await ensureColumn('workouts', 'description', 'TEXT');

    await runAsync(`CREATE TABLE IF NOT EXISTS user_workouts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        exercises TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    await runAsync(`CREATE TABLE IF NOT EXISTS progress_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        weight_kg REAL,
        body_fat REAL,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    await runAsync(`CREATE TABLE IF NOT EXISTS community_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    await runAsync(`CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    await runAsync(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    await runAsync(`CREATE TRIGGER IF NOT EXISTS trg_settings_updated_at
        AFTER UPDATE ON settings
        BEGIN
            UPDATE settings SET updated_at = CURRENT_TIMESTAMP WHERE key = NEW.key;
        END;`);

    await ensureSetting('maintenance_mode', 'false');
    await ensureSetting('welcome_message', 'Bem-vindo à Titanium PRO');

    console.log('Database schema verified.');
}

db.runAsync = runAsync;
db.getAsync = getAsync;
db.allAsync = allAsync;
db.ready = initializeSchema().catch((err) => {
    console.error('Failed to initialize database schema:', err.message);
});

module.exports = db;
