'use strict';

const loadEnv = require('./env');
loadEnv();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./database');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = Number(process.env.PORT || 3000);

const JWT_SECRET = process.env.JWT_SECRET || 'titanium_secret_key_elite_performance';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

const BCRYPT_SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 10);
const ALLOW_MOCK_UPGRADE = process.env.ALLOW_MOCK_UPGRADE === 'true' && NODE_ENV !== 'production';
const ALLOWED_ORIGINS = (process.env.CORS_ORIGIN || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

if (!process.env.JWT_SECRET && NODE_ENV === 'production') {
    console.warn('[WARN] JWT_SECRET não definido. Defina JWT_SECRET para produção.');
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use((req, res, next) => {
    const id = typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : crypto.randomBytes(16).toString('hex');
    req.requestId = id;
    res.setHeader('X-Request-Id', id);
    next();
});
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

    if (NODE_ENV === 'production') {
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
    }
    next();
});
app.use(cors({
    origin: (origin, cb) => {
        if (!origin) return cb(null, true);
        if (ALLOWED_ORIGINS.length === 0) return cb(null, true);

        if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        return cb(new Error('CORS: origin não permitida'));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Access-Token'],
    maxAge: 86400
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({ error: 'JSON inválido.' });
    }
    next(err);
});
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const ms = Date.now() - start;
        console.log(`[${req.requestId}] ${req.method} ${req.originalUrl} ${res.statusCode} ${ms}ms`);
    });
    next();
});

function createRateLimiter({ windowMs, max, keyPrefix }) {
    const buckets = new Map();
    const timer = setInterval(() => {
        const now = Date.now();
        for (const [k, v] of buckets.entries()) {
            if (now > v.resetAt) buckets.delete(k);
        }
    }, Math.min(windowMs, 60_000));
    timer.unref?.();

    return (req, res, next) => {
        const ip = req.ip || req.connection?.remoteAddress || 'unknown';
        const key = `${keyPrefix}:${ip}`;
        const now = Date.now();

        const entry = buckets.get(key);
        if (!entry || now > entry.resetAt) {
            buckets.set(key, { count: 1, resetAt: now + windowMs });
            return next();
        }

        entry.count += 1;
        if (entry.count > max) {
            const retryAfterSec = Math.ceil((entry.resetAt - now) / 1000);
            res.setHeader('Retry-After', String(retryAfterSec));
            return res.status(429).json({ error: 'Muitas tentativas. Tente novamente mais tarde.' });
        }

        next();
    };
}

const authLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 20, keyPrefix: 'auth' });

const PUBLIC_DIR = path.join(__dirname, 'public');
const STATIC_DIR = fs.existsSync(PUBLIC_DIR) ? PUBLIC_DIR : __dirname;
const SENSITIVE_BASENAMES = new Set([
    'server.js',
    'server.improved.js',
    'database.js',
    '.env',
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml'
]);

app.use((req, res, next) => {
    const base = path.basename(req.path || '').toLowerCase();
    if (SENSITIVE_BASENAMES.has(base) || base.endsWith('.sqlite') || base.endsWith('.sqlite3') || base.endsWith('.db')) {
        return res.status(404).end();
    }
    next();
});

app.use(express.static(STATIC_DIR, {
    dotfiles: 'ignore',
    index: false,
    maxAge: NODE_ENV === 'production' ? '1h' : 0,
    setHeaders: (res) => {
        if (NODE_ENV !== 'production') {
            res.setHeader('Cache-Control', 'no-store');
        }
    }
}));

function sendHtml(res, filename) {
    const inPublic = path.join(PUBLIC_DIR, filename);
    const inRoot = path.join(__dirname, filename);
    const target = fs.existsSync(inPublic) ? inPublic : inRoot;
    return res.sendFile(target, (err) => {
        if (err) res.status(404).send('Not Found');
    });
}
app.get('/', (req, res) => sendHtml(res, 'index.html'));
app.get('/dashboard', (req, res) => sendHtml(res, 'dashboard.html'));
app.get('/admin', (req, res) => sendHtml(res, 'admin.html'));
app.get('/login', (req, res) => sendHtml(res, 'login.html'));

function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
    });
}

function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
    });
}

function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) return reject(err);
            resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

async function withTransaction(fn) {
    await dbRun('BEGIN');
    try {
        const result = await fn();
        await dbRun('COMMIT');
        return result;
    } catch (err) {
        try { await dbRun('ROLLBACK'); } catch (_) {  }
        throw err;
    }
}

const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

function isNonEmptyString(v) {
    return typeof v === 'string' && v.trim().length > 0;
}

function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPassword(pw) {
    return typeof pw === 'string' && pw.length >= 8 && pw.length <= 72;
}

function safeJsonParse(str, fallback) {
    try {
        return JSON.parse(str);
    } catch {
        return fallback;
    }
}

function issueToken(userId) {
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function getTokenFromRequest(req) {
    const auth = req.headers.authorization;
    if (typeof auth === 'string' && auth.toLowerCase().startsWith('bearer ')) {
        return auth.slice(7).trim();
    }

    const legacy = req.headers['x-access-token'];
    if (typeof legacy === 'string') return legacy.trim();
    if (Array.isArray(legacy) && legacy.length > 0) return String(legacy[0]).trim();

    return null;
}

function verifyToken(req, res, next) {
    const token = getTokenFromRequest(req);
    if (!token) return res.status(403).json({ error: 'Nenhum token fornecido.' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Falha ao autenticar token.' });
        req.userId = decoded.id;
        next();
    });
}

const attachUser = asyncHandler(async (req, res, next) => {
    const user = await dbGet(
        'SELECT id, name, email, whatsapp, plan, role, created_at FROM users WHERE id = ?',
        [req.userId]
    );

    if (!user) return res.status(401).json({ error: 'Usuário não encontrado.' });

    req.user = {
        ...user,
        plan: user.plan || 'free',
        role: user.role || 'user'
    };

    next();
});

function requireAdmin(req, res, next) {
    if (req.user?.role !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado. Requer privilégios de Administrador.' });
    }
    next();
}

function requirePlans(plans) {
    return (req, res, next) => {
        const plan = req.user?.plan || 'free';
        if (!plans.includes(plan)) {
            return res.status(403).json({ error: 'Conteúdo exclusivo para membros Elite.', plan });
        }
        next();
    };
}

const maintenanceGuard = asyncHandler(async (req, res, next) => {
    const row = await dbGet("SELECT value FROM settings WHERE key = 'maintenance_mode'");
    const on = row && String(row.value).toLowerCase() === 'true';

    if (on && req.user?.role !== 'admin') {
        return res.status(503).json({
            error: 'Sistema em manutenção. Tente novamente mais tarde.',
            maintenance: true
        });
    }

    next();
});

async function logAction(userId, action, details, meta = null) {
    const ip = meta?.ip;
    const extra = ip ? ` | ip=${ip}` : '';

    try {
        await dbRun(
            'INSERT INTO logs (user_id, action, details) VALUES (?, ?, ?)',
            [userId, action, `${details}${extra}`]
        );
    } catch (err) {
        console.error('Logging Error:', err.message);
    }
}

const api = express.Router();

api.get('/health', (req, res) => {
    res.status(200).json({ ok: true, env: NODE_ENV, uptime: Math.round(process.uptime()) });
});

api.post('/register', authLimiter, asyncHandler(async (req, res) => {
    const name = String(req.body?.name || '').trim();
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || '');
    const whatsapp = isNonEmptyString(req.body?.whatsapp) ? String(req.body.whatsapp).trim() : null;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Campos obrigatórios.' });
    }
    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Email inválido.' });
    }
    if (!isValidPassword(password)) {
        return res.status(400).json({ error: 'Senha deve ter entre 8 e 72 caracteres.' });
    }

    const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

    try {
        const userId = await withTransaction(async () => {
            const insert = await dbRun(
                "INSERT INTO users (name, email, password, whatsapp, plan, role) VALUES (?, ?, ?, ?, 'free', 'user')",
                [name, email, hashedPassword, whatsapp]
            );

            await dbRun('INSERT INTO user_stats (user_id) VALUES (?)', [insert.lastID]);
            return insert.lastID;
        });

        const token = issueToken(userId);
        await logAction(userId, 'REGISTER', `Novo cadastro: ${email}`, { ip: req.ip });

        res.status(201).json({
            message: 'Registrado.',
            token,
            user: { name, email, plan: 'free', role: 'user' }
        });
    } catch (err) {
        const msg = String(err.message || '');
        if (msg.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Email já cadastrado.' });
        }
        throw err;
    }
}));

api.post('/login', authLimiter, asyncHandler(async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || '');

    if (!email || !password) {
        return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
    }

    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });

    const passwordIsValid = await bcrypt.compare(password, user.password);
    if (!passwordIsValid) return res.status(401).json({ error: 'Senha inválida.' });

    const token = issueToken(user.id);
    await logAction(user.id, 'LOGIN', 'Login realizado', { ip: req.ip });

    res.status(200).json({
        auth: true,
        token,
        user: {
            name: user.name,
            email: user.email,
            plan: user.plan,
            role: user.role || 'user'
        }
    });
}));

const protectedApi = express.Router();

protectedApi.use(verifyToken, attachUser, maintenanceGuard);

protectedApi.get('/dashboard', asyncHandler(async (req, res) => {
    const sql = `
    SELECT u.name, u.plan, s.streak_days, s.total_load_kg, s.monthly_checkins
    FROM users u
    LEFT JOIN user_stats s ON u.id = s.user_id
    WHERE u.id = ?
  `;

    const data = await dbGet(sql, [req.user.id]);
    res.status(200).json(data);
}));
protectedApi.post('/upgrade', asyncHandler(async (req, res) => {
    if (!ALLOW_MOCK_UPGRADE) {
        return res.status(404).json({ error: 'Rota não encontrada.' });
    }

    await dbRun("UPDATE users SET plan = 'black' WHERE id = ?", [req.user.id]);
    await logAction(req.user.id, 'MOCK_UPGRADE', 'Upgrade mock para black', { ip: req.ip });

    res.status(200).json({ success: true, plan: 'black' });
}));
protectedApi.get('/workouts', requirePlans(['black', 'iron']), asyncHandler(async (req, res) => {
    const rows = await dbAll('SELECT * FROM workouts');
    res.status(200).json(rows);
}));

protectedApi.get('/my-workouts', asyncHandler(async (req, res) => {
    const rows = await dbAll(
        'SELECT * FROM user_workouts WHERE user_id = ? ORDER BY created_at DESC',
        [req.user.id]
    );

    const out = rows.map(r => ({
        ...r,
        exercises: safeJsonParse(r.exercises, [])
    }));

    res.status(200).json(out);
}));

protectedApi.post('/my-workouts', asyncHandler(async (req, res) => {
    const name = String(req.body?.name || '').trim();
    const exercises = req.body?.exercises;

    if (!name) {
        return res.status(400).json({ error: 'Nome é obrigatório.' });
    }
    if (!Array.isArray(exercises) || exercises.length === 0) {
        return res.status(400).json({ error: 'Exercícios são obrigatórios.' });
    }
    if (exercises.length > 200) {
        return res.status(400).json({ error: 'Limite de exercícios excedido.' });
    }

    const insert = await dbRun(
        'INSERT INTO user_workouts (user_id, name, exercises) VALUES (?, ?, ?)',
        [req.user.id, name, JSON.stringify(exercises)]
    );

    await logAction(req.user.id, 'WORKOUT_CREATE', `Criou treino: ${name}`, { ip: req.ip });

    res.status(201).json({ id: insert.lastID, name, exercises });
}));

protectedApi.delete('/my-workouts/:id', asyncHandler(async (req, res) => {
    const workoutId = Number(req.params.id);
    if (!Number.isInteger(workoutId) || workoutId <= 0) {
        return res.status(400).json({ error: 'ID inválido.' });
    }

    const result = await dbRun(
        'DELETE FROM user_workouts WHERE id = ? AND user_id = ?',
        [workoutId, req.user.id]
    );

    if (result.changes === 0) {
        return res.status(404).json({ error: 'Treino não encontrado.' });
    }

    await logAction(req.user.id, 'WORKOUT_DELETE', `Excluiu treino ID ${workoutId}`, { ip: req.ip });

    res.status(200).json({ success: true });
}));

protectedApi.get('/progress', asyncHandler(async (req, res) => {
    const rows = await dbAll(
        'SELECT * FROM progress_entries WHERE user_id = ? ORDER BY created_at DESC',
        [req.user.id]
    );
    res.status(200).json(rows);
}));

protectedApi.post('/progress', asyncHandler(async (req, res) => {
    const weight_kg = req.body?.weight_kg;
    const body_fat = req.body?.body_fat;
    const notes = isNonEmptyString(req.body?.notes) ? String(req.body.notes).trim() : null;
    const w = (weight_kg === undefined || weight_kg === null) ? null : Number(weight_kg);
    const bf = (body_fat === undefined || body_fat === null) ? null : Number(body_fat);

    if (w !== null && (!Number.isFinite(w) || w <= 0 || w > 500)) {
        return res.status(400).json({ error: 'weight_kg inválido.' });
    }
    if (bf !== null && (!Number.isFinite(bf) || bf < 0 || bf > 100)) {
        return res.status(400).json({ error: 'body_fat inválido.' });
    }

    const insert = await dbRun(
        'INSERT INTO progress_entries (user_id, weight_kg, body_fat, notes) VALUES (?, ?, ?, ?)',
        [req.user.id, w, bf, notes]
    );

    await logAction(req.user.id, 'PROGRESS_CREATE', 'Criou registro de progresso', { ip: req.ip });

    res.status(201).json({ id: insert.lastID });
}));

protectedApi.get('/community', asyncHandler(async (req, res) => {
    const sql = `
    SELECT p.id, p.content, p.created_at, u.name as author_name, u.plan as author_plan
    FROM community_posts p
    JOIN users u ON p.user_id = u.id
    ORDER BY p.created_at DESC
    LIMIT 50
  `;

    const rows = await dbAll(sql);
    res.status(200).json(rows);
}));

protectedApi.post('/community', asyncHandler(async (req, res) => {
    const content = String(req.body?.content || '').trim();
    if (!content) return res.status(400).json({ error: 'Conteúdo vazio.' });
    if (content.length > 2000) return res.status(400).json({ error: 'Conteúdo muito grande.' });

    const insert = await dbRun(
        'INSERT INTO community_posts (user_id, content) VALUES (?, ?)',
        [req.user.id, content]
    );

    await logAction(req.user.id, 'COMMUNITY_POST', 'Criou post na comunidade', { ip: req.ip });

    res.status(201).json({ id: insert.lastID });
}));

protectedApi.get('/profile', asyncHandler(async (req, res) => {
    const { id, name, email, whatsapp, plan, created_at } = req.user;
    res.status(200).json({ id, name, email, whatsapp, plan, created_at });
}));

protectedApi.put('/profile', asyncHandler(async (req, res) => {
    const name = isNonEmptyString(req.body?.name) ? String(req.body.name).trim() : null;
    const whatsapp = isNonEmptyString(req.body?.whatsapp) ? String(req.body.whatsapp).trim() : null;

    if (!name) return res.status(400).json({ error: 'Nome é obrigatório.' });

    await dbRun('UPDATE users SET name = ?, whatsapp = ? WHERE id = ?', [name, whatsapp, req.user.id]);
    await logAction(req.user.id, 'PROFILE_UPDATE', 'Atualizou perfil', { ip: req.ip });

    res.status(200).json({ success: true });
}));

const adminApi = express.Router();
adminApi.use(requireAdmin);

adminApi.get('/stats', asyncHandler(async (req, res) => {
    const [totalRow, blackRow, ironRow] = await Promise.all([
        dbGet('SELECT COUNT(*) as total FROM users'),
        dbGet("SELECT COUNT(*) as black FROM users WHERE plan = 'black'"),
        dbGet("SELECT COUNT(*) as iron FROM users WHERE plan = 'iron'")
    ]);

    res.status(200).json({
        totalUsers: totalRow?.total || 0,
        blackUsers: blackRow?.black || 0,
        ironUsers: ironRow?.iron || 0
    });
}));

adminApi.get('/logs', asyncHandler(async (req, res) => {
    const sql = `
    SELECT l.id, l.action, l.details, l.created_at, u.name as user_name
    FROM logs l
    LEFT JOIN users u ON l.user_id = u.id
    ORDER BY l.created_at DESC
    LIMIT 50
  `;
    const rows = await dbAll(sql);
    res.status(200).json(rows);
}));

adminApi.get('/analytics', asyncHandler(async (req, res) => {
    const planDistribution = await dbAll('SELECT plan, COUNT(*) as count FROM users GROUP BY plan');
    const recentRegistrations = await dbAll('SELECT name, email, plan, created_at FROM users ORDER BY created_at DESC LIMIT 10');

    res.status(200).json({ planDistribution, recentRegistrations });
}));

adminApi.get('/users', asyncHandler(async (req, res) => {
    const rows = await dbAll('SELECT id, name, email, whatsapp, plan, role, created_at FROM users ORDER BY created_at DESC');
    res.status(200).json(rows);
}));

adminApi.post('/user/update-plan', asyncHandler(async (req, res) => {
    const userId = Number(req.body?.userId);
    const newPlan = String(req.body?.newPlan || '').trim();

    const allowedPlans = new Set(['free', 'black', 'iron']);
    if (!Number.isInteger(userId) || userId <= 0) {
        return res.status(400).json({ error: 'userId inválido.' });
    }
    if (!allowedPlans.has(newPlan)) {
        return res.status(400).json({ error: 'newPlan inválido.' });
    }

    const result = await dbRun('UPDATE users SET plan = ? WHERE id = ?', [newPlan, userId]);
    if (result.changes === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });

    await logAction(req.user.id, 'USER_UPDATE', `Alterou plano do user ${userId} para ${newPlan}`, { ip: req.ip });

    res.status(200).json({ success: true });
}));

adminApi.delete('/user/:id', asyncHandler(async (req, res) => {
    const targetId = Number(req.params.id);
    if (!Number.isInteger(targetId) || targetId <= 0) {
        return res.status(400).json({ error: 'ID inválido.' });
    }
    if (targetId === req.user.id) {
        return res.status(400).json({ error: 'Não é possível excluir a si mesmo.' });
    }
    const changes = await withTransaction(async () => {
        await dbRun('DELETE FROM user_stats WHERE user_id = ?', [targetId]);
        await dbRun('DELETE FROM progress_entries WHERE user_id = ?', [targetId]);
        await dbRun('DELETE FROM community_posts WHERE user_id = ?', [targetId]);
        await dbRun('DELETE FROM user_workouts WHERE user_id = ?', [targetId]);
        await dbRun('DELETE FROM logs WHERE user_id = ?', [targetId]);
        const result = await dbRun('DELETE FROM users WHERE id = ?', [targetId]);
        return result.changes;
    });

    if (changes === 0) return res.status(404).json({ error: 'Usuário não encontrado.' });

    await logAction(req.user.id, 'USER_DELETE', `Excluiu usuário ID ${targetId}`, { ip: req.ip });

    res.status(200).json({ success: true });
}));

adminApi.get('/settings', asyncHandler(async (req, res) => {
    const rows = await dbAll('SELECT * FROM settings');
    const settings = {};
    for (const r of rows) settings[r.key] = r.value;
    res.status(200).json(settings);
}));

adminApi.post('/settings', asyncHandler(async (req, res) => {
    const key = String(req.body?.key || '').trim();
    const value = String(req.body?.value ?? '').trim();

    if (!key) return res.status(400).json({ error: 'key é obrigatório.' });
    if (key.length > 100) return res.status(400).json({ error: 'key muito grande.' });
    if (value.length > 5000) return res.status(400).json({ error: 'value muito grande.' });

    await dbRun('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', [key, value]);
    await logAction(req.user.id, 'SETTINGS_UPDATE', `Alterou ${key} para ${value}`, { ip: req.ip });

    res.status(200).json({ success: true });
}));
protectedApi.use('/admin', adminApi);
api.use(protectedApi);
app.use('/api', api);

app.use('/api', (req, res) => {
    res.status(404).json({ error: 'Rota não encontrada.' });
});

app.use((err, req, res, next) => {
    console.error(`[${req.requestId}]`, err);
    if (String(err?.message || '').startsWith('CORS:')) {
        return res.status(403).json({ error: 'CORS bloqueou a requisição.' });
    }

    if (res.headersSent) return next(err);

    const status = err?.statusCode && Number.isInteger(err.statusCode) ? err.statusCode : 500;
    const message = (NODE_ENV === 'production' && status >= 500)
        ? 'Erro interno.'
        : (err?.message || 'Erro interno.');

    res.status(status).json({ error: message });
});

const server = app.listen(PORT, () => {
    console.log(`Titanium Server running on Port ${PORT} (env=${NODE_ENV})`);
});

server.on('error', (error) => {
    if (error.syscall !== 'listen') throw error;

    const bind = typeof PORT === 'string' ? 'Pipe ' + PORT : 'Port ' + PORT;
    switch (error.code) {
        case 'EACCES':
            console.error(bind + ' requires elevated privileges');
            process.exit(1);
            break;
        case 'EADDRINUSE':
            console.error(bind + ' is already in use');
            process.exit(1);
            break;
        default:
            throw error;
    }
});

function shutdown(signal) {
    console.log(`Received ${signal}. Shutting down...`);
    server.close(() => {
        if (typeof db.close === 'function') {
            try {
                db.close(() => console.log('DB connection closed.'));
            } catch (e) {
                console.error('Error closing DB:', e);
            }
        }
        process.exit(0);
    });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

