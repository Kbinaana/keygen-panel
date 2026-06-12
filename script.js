const SECRET_KEY = 'MyModLoaderSecretKey2024';

function getSecret() {
    return localStorage.getItem('keygen_secret') || SECRET_KEY;
}

function saveSecret(val) {
    localStorage.setItem('keygen_secret', val);
}

function randomChar() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    return chars[Math.floor(Math.random() * chars.length)];
}

async function hmacSign(data, secret) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw', enc.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
    const hash = Array.from(new Uint8Array(sig))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
        .toUpperCase();
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let shortSig = '';
    for (let i = 0; i < 4; i++) {
        const idx = parseInt(hash.substring(i * 8, i * 8 + 8), 16) % 36;
        shortSig += chars[idx];
    }
    return shortSig;
}

async function generateKey(format, prefix, serial, secret, expiryDays) {
    let key = '';
    for (const ch of format) {
        key += ch === 'X' ? randomChar() : ch;
    }
    const serialStr = serial ? `-${String(serial).padStart(4, '0')}` : '';
    const dateStr = expiryDays > 0 ? `-${String(expiryDays)}D` : '';
    const baseKey = prefix + key + serialStr + dateStr;
    if (secret) {
        const sig = await hmacSign(baseKey, secret);
        return `${baseKey}-${sig}`;
    }
    return baseKey;
}

async function generateKeys() {
    const format = document.getElementById('format').value;
    let count = Math.min(Math.max(parseInt(document.getElementById('count').value) || 1, 1), 500);
    const prefix = document.getElementById('prefix').value.toUpperCase().trim();
    const serialStart = parseInt(document.getElementById('serialStart').value) || 0;
    const expiryDays = parseInt(document.getElementById('expiry').value) || 0;
    const useHmac = document.getElementById('hmacToggle').checked;
    const secret = useHmac ? getSecret() : '';
    const list = document.getElementById('keyList');
    list.innerHTML = '';
    const keys = [];
    for (let i = 0; i < count; i++) {
        const serial = serialStart > 0 ? serialStart + i : 0;
        const key = await generateKey(format, prefix, serial, secret, expiryDays);
        keys.push({ key, serial, expiryDays });
    }
    renderKeys(keys);
    document.getElementById('keyCount').textContent = `${keys.length} keys`;
    document.getElementById('copyAllBtn').disabled = false;
    document.getElementById('exportBtn').disabled = false;
}

function renderKeys(keys) {
    const list = document.getElementById('keyList');
    list.innerHTML = '';
    keys.forEach(({ key, serial, expiryDays }) => {
        const div = document.createElement('div');
        div.className = 'key-item';
        const serialStr = serial > 0 ? `#${String(serial).padStart(4, '0')}` : '';
        const expiryStr = expiryDays > 0 ? `${expiryDays}D` : '';
        div.innerHTML = `
            ${serialStr ? `<span class="key-serial">${serialStr}</span>` : ''}
            <span class="key-text">${key}</span>
            ${expiryStr ? `<span class="key-expiry">${expiryStr}</span>` : ''}
            <span class="key-copied">Copied!</span>
        `;
        div.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(key);
                div.classList.add('copied');
                setTimeout(() => div.classList.remove('copied'), 1200);
            } catch {}
        });
        list.appendChild(div);
    });
}

async function validateKey() {
    const input = document.getElementById('validateInput').value.trim();
    const result = document.getElementById('validateResult');
    if (!input) {
        result.className = 'invalid';
        result.textContent = 'Please enter a key to validate.';
        result.style.display = 'block';
        return;
    }
    const secret = getSecret();
    const sig = input.split('-').pop();
    const baseKey = input.substring(0, input.lastIndexOf('-'));
    if (baseKey.includes('--')) {
        result.className = 'invalid';
        result.textContent = 'Invalid key format.';
        result.style.display = 'block';
        return;
    }
    const expectedSig = await hmacSign(baseKey, secret);
    if (sig === expectedSig) {
        result.className = 'valid';
        const match = baseKey.match(/-(\d+)D$/);
        const expiryInfo = match
            ? `Expires in ${match[1]} days from generation.`
            : 'No expiry set.';
        result.textContent = `Valid key! ${expiryInfo}`;
    } else {
        result.className = 'invalid';
        result.textContent = 'Invalid key - signature mismatch.';
    }
    result.style.display = 'block';
}

function exportTxt() {
    const items = document.querySelectorAll('.key-item .key-text');
    if (!items.length) return;
    const keys = Array.from(items).map(el => el.textContent).join('\n');
    const blob = new Blob([keys], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `keys_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
}

function copyAll() {
    const items = document.querySelectorAll('.key-item .key-text');
    if (!items.length) return;
    const text = Array.from(items).map(el => el.textContent).join('\n');
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('copyAllBtn');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy All'; }, 2000);
    });
}

function clearOutput() {
    document.getElementById('keyList').innerHTML = '';
    document.getElementById('keyCount').textContent = '0 keys';
    document.getElementById('copyAllBtn').disabled = true;
    document.getElementById('exportBtn').disabled = true;
}

document.getElementById('generateBtn').addEventListener('click', generateKeys);
document.getElementById('copyAllBtn').addEventListener('click', copyAll);
document.getElementById('exportBtn').addEventListener('click', exportTxt);
document.getElementById('clearBtn').addEventListener('click', clearOutput);
document.getElementById('validateBtn').addEventListener('click', validateKey);

document.getElementById('saveSecretBtn').addEventListener('click', () => {
    const val = document.getElementById('secretKey').value.trim();
    if (val) {
        saveSecret(val);
        alert('Secret saved! Use same secret to validate keys.');
    }
});

document.getElementById('randomSecretBtn').addEventListener('click', () => {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    const secret = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    document.getElementById('secretKey').value = secret;
    saveSecret(secret);
    alert('Random secret generated and saved!');
});

document.getElementById('validateInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') validateKey();
});

document.getElementById('secretKey').value = getSecret();

document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(btn.dataset.tab + 'Tab').classList.add('active');
    });
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target.closest('#generateTab') && e.target.tagName !== 'TEXTAREA') {
        generateKeys();
    }
});

generateKeys();
