const fs = require('fs');
const path = require('path');

function parseValue(raw) {
    const trimmed = raw.trim();
    if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
        return trimmed.slice(1, -1);
    }
    return trimmed;
}

function loadEnv(customPath) {
    const envPath = customPath || path.resolve(__dirname, '.env');
    if (!fs.existsSync(envPath)) return;

    const content = fs.readFileSync(envPath, 'utf8');
    const lines = content.split(/\r?\n/);

    for (const line of lines) {
        if (!line || line.trim().startsWith('#')) continue;
        const idx = line.indexOf('=');
        if (idx === -1) continue;

        const key = line.slice(0, idx).trim();
        const value = parseValue(line.slice(idx + 1));

        if (key && !Object.prototype.hasOwnProperty.call(process.env, key)) {
            process.env[key] = value;
        }
    }
}

module.exports = loadEnv;
