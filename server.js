const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'MyModLoaderSecretKey2024';
const DB_FILE = './keys.json';

function loadDB() {
    try {
        if (fs.existsSync(DB_FILE)) {
            return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
        }
    } catch (e) { console.error('DB load error:', e); }
    return [];
}

function saveDB(db) {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function hmacSign(data, secret) {
    return crypto.createHmac('sha256', secret).update(data).digest('hex').toUpperCase().split('').filter(c => /[A-Z0-9]/.test(c)).slice(0, 4).join('');
}

function getKeyStatus(k) {
    if (k.status === 'revoked') return 'revoked';
    if (k.expiresAt && Date.now() > k.expiresAt) return 'expired';
    return 'active';
}

app.get('/api/validate', (req, res) => {
    const key = req.query.key;
    const format = req.query.format;

    if (!key) {
        return res.json({ status: false, reason: 'No key provided' });
    }

    const db = loadDB();
    const parts = key.split('-');
    const sig = parts.pop();
    const baseKey = parts.join('-');
    const expectedSig = hmacSign(baseKey, SECRET_KEY);
    const sigValid = sig === expectedSig;

    const dbKey = db.find(k => k.key === key);
    const status = dbKey ? getKeyStatus(dbKey) : 'unknown';

    if (dbKey && status === 'active') {
        dbKey.lastUsedAt = Date.now();
        saveDB(db);
    }

    const isGood = sigValid && status === 'active';
    const authData = `PUBG-${key}-${dbKey && dbKey.lastUsedAt ? dbKey.lastUsedAt : '0'}-Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz9E`;
    const token = hmacSign(authData, SECRET_KEY) + key.substr(0, 8);

    const response = {
        status: isGood,
        reason: isGood ? '' : (!sigValid ? 'Invalid signature' : `Key ${status}`),
        data: isGood ? {
            token: token,
            rng: Math.floor(Date.now() / 1000),
            modname: 'NEXUS MOD MENU',
            mod_status: 'Connected'
        } : null
    };

    if (format === 'json') {
        return res.json(response);
    }

    if (!isGood) {
        return res.send('Invalid key');
    }
    return res.send('OK');
});

app.get('/api/keys', (req, res) => {
    const db = loadDB();
    const secret = req.query.secret;
    if (secret !== SECRET_KEY) return res.status(403).json({ error: 'Unauthorized' });
    res.json(db);
});

app.post('/api/key/add', express.json(), (req, res) => {
    const { key, user, expiryDays, status, secret } = req.body;
    if (secret !== SECRET_KEY) return res.status(403).json({ error: 'Unauthorized' });
    if (!key) return res.json({ status: false, reason: 'No key' });

    const db = loadDB();
    if (db.find(k => k.key === key)) return res.json({ status: false, reason: 'Key exists' });

    db.push({
        id: Date.now().toString(36) + Math.random().toString(36).substr(2, 4),
        key: key,
        serial: 0,
        user: user || '',
        status: status || 'active',
        expiresAt: expiryDays > 0 ? Date.now() + expiryDays * 86400000 : null,
        createdAt: Date.now(),
        lastUsedAt: null
    });
    saveDB(db);
    res.json({ status: true, reason: 'Key added' });
});

app.post('/api/sync', express.json({limit: '50mb'}), (req, res) => {
    const { keys, secret } = req.body;
    if (secret !== SECRET_KEY) return res.status(403).json({ error: 'Unauthorized' });
    if (!Array.isArray(keys)) return res.json({ status: false, reason: 'Invalid data' });
    saveDB(keys);
    res.json({ status: true, reason: `Synced ${keys.length} keys` });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`KeyMaster API running on port ${PORT}`);
});
