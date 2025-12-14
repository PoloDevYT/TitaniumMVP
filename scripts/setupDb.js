const path = require('path');
const bcrypt = require('bcryptjs');

const loadEnv = require('../env');
loadEnv(path.resolve(__dirname, '..', '.env'));

const db = require('../database');

async function seedAdminUser() {
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@titanium.local';
    const adminPassword = process.env.ADMIN_PASSWORD || 'changeme-admin';
    const adminName = process.env.ADMIN_NAME || 'Administrator';
    const plan = process.env.ADMIN_PLAN || 'black';

    const existing = await db.getAsync('SELECT id FROM users WHERE email = ?', [adminEmail]);
    const hashed = await bcrypt.hash(adminPassword, 10);

    if (existing) {
        await db.runAsync(
            "UPDATE users SET name = ?, password = ?, role = 'admin', plan = ? WHERE email = ?",
            [adminName, hashed, plan, adminEmail]
        );
        console.log('Admin user updated.');
        return existing.id;
    }

    const result = await db.runAsync(
        "INSERT INTO users (name, email, password, whatsapp, plan, role) VALUES (?, ?, ?, ?, ?, 'admin')",
        [adminName, adminEmail, hashed, '0000000000', plan]
    );
    await db.runAsync('INSERT OR IGNORE INTO user_stats (user_id) VALUES (?)', [result.lastID]);
    console.log('Admin user created.');
    return result.lastID;
}

async function seedWorkouts() {
    const existing = await db.getAsync('SELECT COUNT(*) as count FROM workouts');
    if (existing && existing.count > 0) {
        console.log('Workouts already present, skipping seed.');
        return;
    }

    const catalog = [
        {
            title: 'Protocolo Iron Core',
            level: 'intermediário',
            focus: 'força e estabilidade',
            duration_minutes: 45,
            equipment: 'máquinas guiadas, anilhas, halteres',
            description: 'Circuito concentrado em básicos com tempo de tensão prolongado.'
        },
        {
            title: 'Sprint Titanium',
            level: 'avançado',
            focus: 'condicionamento e potência',
            duration_minutes: 30,
            equipment: 'bike erg, prowler, kettlebell',
            description: 'Blocos intervalados de alta intensidade para VO2 e explosão muscular.'
        },
        {
            title: 'Hypertrophy Black',
            level: 'avançado',
            focus: 'hipertrofia',
            duration_minutes: 60,
            equipment: 'máquinas premium, barras olímpicas',
            description: 'Split push/pull/legs com progressão linear e técnicas de intensificação.'
        }
    ];

    for (const item of catalog) {
        await db.runAsync(
            `INSERT INTO workouts (title, level, focus, duration_minutes, equipment, description)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [item.title, item.level, item.focus, item.duration_minutes, item.equipment, item.description]
        );
    }

    console.log('Seeded default workout catalog.');
}

async function run() {
    try {
        await db.ready;
        const adminId = await seedAdminUser();
        await seedWorkouts();
        console.log(`Database ready. Admin ID: ${adminId}`);
        process.exit(0);
    } catch (err) {
        console.error('Setup failed:', err);
        process.exit(1);
    }
}

run();
