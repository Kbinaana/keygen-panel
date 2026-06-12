const SECRET_KEY = 'MyModLoaderSecretKey2024';
let db = [];
let currentFilter = 'all';
let editingKeyId = null;

function getSecret() { return localStorage.getItem('keygen_secret') || SECRET_KEY; }
function saveSecret(val) { localStorage.setItem('keygen_secret', val); }

function loadDB() {
    try { db = JSON.parse(localStorage.getItem('keygen_db')) || []; }
    catch { db = []; }
}

function saveDB() {
    localStorage.setItem('keygen_db', JSON.stringify(db));
    updateStats();
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substring(2, 6);
}

function randomChar() {
    return 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[Math.floor(Math.random() * 36)];
}

async function hmacSign(data, secret) {
    try {
        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
        const hash = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let shortSig = '';
        for (let i = 0; i < 4; i++) shortSig += chars[parseInt(hash.substring(i * 8, i * 8 + 8), 16) % 36];
        return shortSig;
    } catch {
        let hash = 0;
        for (let i = 0; i < data.length; i++) hash = ((hash << 5) - hash) + data.charCodeAt(i);
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        return (Math.abs(hash) % 1679616).toString(36).toUpperCase().padStart(4, '0').split('').map(c => chars[parseInt(c, 36) % 36]).join('');
    }
}

async function generateKey(format, prefix, serial, secret, expiryDays) {
    let key = '';
    for (const ch of format) key += ch === 'X' ? randomChar() : ch;
    const serialStr = serial ? `-${String(serial).padStart(4, '0')}` : '';
    const expiryStr = expiryDays > 0 ? `-${expiryDays}D` : '';
    const baseKey = prefix + key + serialStr + expiryStr;
    if (secret) return `${baseKey}-${await hmacSign(baseKey, secret)}`;
    return baseKey;
}

function computeExpiry(days) { return days > 0 ? Date.now() + days * 86400000 : null; }
function isExpired(k) { return k.expiresAt && Date.now() > k.expiresAt; }
function getKeyStatus(k) { return k.status === 'revoked' ? 'revoked' : isExpired(k) ? 'expired' : 'active'; }

// ===== TOAST =====

function showToast(msg, type) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'toast show ' + (type || 'info');
    clearTimeout(t._hide);
    t._hide = setTimeout(() => { t.className = 'toast'; }, 3000);
}

// ===== GENERATE =====

async function generateKeys() {
    try {
        const format = document.getElementById('format').value;
        let count = Math.min(Math.max(parseInt(document.getElementById('count').value) || 1, 1), 500);
        const prefix = document.getElementById('prefix').value.toUpperCase().trim();
        const serialStart = parseInt(document.getElementById('serialStart').value) || 0;
        const expiryDays = parseInt(document.getElementById('expiry').value) || 0;
        const useHmac = document.getElementById('hmacToggle').checked;
        const secret = useHmac ? getSecret() : '';
        const assignUser = document.getElementById('assignUser').value.trim();

        const list = document.getElementById('keyList');
        list.innerHTML = '<div class="key-item" style="color:var(--text-muted);cursor:default;justify-content:center;font-family:var(--font)">Generating keys...</div>';

        const items = [];
        for (let i = 0; i < count; i++) {
            const serial = serialStart > 0 ? serialStart + i : 0;
            const key = await generateKey(format, prefix, serial, secret, expiryDays);
            items.push({ key, serial, expiryDays, user: assignUser });
        }

        renderGeneratedKeys(items);
        document.getElementById('keyCount').textContent = `${items.length} keys`;
        document.getElementById('saveKeysBtn').disabled = false;
        document.getElementById('copyAllBtn').disabled = false;
        document.getElementById('exportBtn').disabled = false;
        document.getElementById('saveKeysBtn')._items = items;
        showToast(`Generated ${items.length} keys`, 'success');
    } catch (e) {
        console.error(e);
        showToast('Error generating keys: ' + e.message, 'error');
    }
}

function renderGeneratedKeys(items) {
    const list = document.getElementById('keyList');
    list.innerHTML = '';
    items.forEach(({ key, serial, expiryDays, user }) => {
        const div = document.createElement('div');
        div.className = 'key-item';
        const serialStr = serial > 0 ? `#${String(serial).padStart(4, '0')}` : '';
        const expiryStr = expiryDays > 0 ? `${expiryDays}D` : '';
        div.innerHTML = `
            ${serialStr ? `<span class="key-serial">${serialStr}</span>` : ''}
            <span class="key-text">${key}</span>
            ${user ? `<span class="key-user">${user}</span>` : ''}
            ${expiryStr ? `<span class="key-expiry">${expiryStr}</span>` : ''}
            <span class="key-copied">Copied!</span>
        `;
        div.addEventListener('click', () => {
            navigator.clipboard.writeText(key).then(() => {
                div.classList.add('copied');
                setTimeout(() => div.classList.remove('copied'), 1200);
                showToast('Key copied!', 'success');
            });
        });
        list.appendChild(div);
    });
}

function saveGeneratedKeys() {
    const btn = document.getElementById('saveKeysBtn');
    const items = btn._items || [];
    if (!items.length) return;
    for (const item of items) {
        db.push({ id: generateId(), key: item.key, serial: item.serial, user: item.user || '', status: 'active', expiresAt: computeExpiry(item.expiryDays), createdAt: Date.now() });
    }
    saveDB();
    renderManageTable();
    showToast(`Saved ${items.length} keys to database`, 'success');
    btn.textContent = 'Saved!';
    setTimeout(() => { btn.textContent = '💾 Save'; }, 2000);
}

function copyAll() {
    const texts = Array.from(document.querySelectorAll('.key-item .key-text')).map(el => el.textContent);
    if (!texts.length) return;
    navigator.clipboard.writeText(texts.join('\n')).then(() => {
        const btn = document.getElementById('copyAllBtn');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = '📋 Copy'; }, 2000);
        showToast('All keys copied!', 'success');
    });
}

function exportTxt() {
    const texts = Array.from(document.querySelectorAll('.key-item .key-text')).map(el => el.textContent);
    if (!texts.length) return;
    const blob = new Blob([texts.join('\n')], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `keys_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
    showToast('File exported', 'success');
}

function clearOutput() {
    document.getElementById('keyList').innerHTML = '';
    document.getElementById('keyCount').textContent = '0 keys';
    document.getElementById('saveKeysBtn').disabled = true;
    document.getElementById('copyAllBtn').disabled = true;
    document.getElementById('exportBtn').disabled = true;
}

// ===== MANAGE =====

function getLastUsedStr(k) {
    if (!k.lastUsedAt) return 'Never';
    const diff = Date.now() - k.lastUsedAt;
    if (diff < 60000) return 'Now';
    if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
    return `${Math.floor(diff/86400000)}d ago`;
}

function isOnline(k) {
    return k.lastUsedAt && (Date.now() - k.lastUsedAt) < 86400000;
}

function renderManageTable() {
    const container = document.getElementById('manageTable');
    const searchTerm = (document.getElementById('searchInput').value || '').toLowerCase();
    let filtered = [...db];

    if (currentFilter === 'active') filtered = filtered.filter(k => getKeyStatus(k) === 'active');
    else if (currentFilter === 'expired') filtered = filtered.filter(k => getKeyStatus(k) === 'expired');
    else if (currentFilter === 'revoked') filtered = filtered.filter(k => getKeyStatus(k) === 'revoked');

    if (searchTerm) {
        filtered = filtered.filter(k => k.key.toLowerCase().includes(searchTerm) || k.user.toLowerCase().includes(searchTerm));
    }

    const activeUsers = new Set(filtered.filter(k => getKeyStatus(k) === 'active' && k.user).map(k => k.user));
    const onlineUsers = new Set(filtered.filter(k => getKeyStatus(k) === 'active' && k.user && isOnline(k)).map(k => k.user));

    document.getElementById('navBadge').textContent = filtered.length;
    document.getElementById('navBadge').style.display = filtered.length ? 'inline' : 'none';

    let html = `<div class="table-row header">
        <input type="checkbox" id="selectAll">
        <span>Key</span><span>User</span><span>Status</span><span>Last Used</span><span>Expiry</span><span>Actions</span>
    </div>`;

    if (!filtered.length) {
        html += `<div class="table-row" style="justify-content:center;padding:1.5rem;color:var(--text-muted);font-family:var(--font);min-width:auto;grid-template-columns:1fr">No keys found.</div>`;
        container.innerHTML = html;
        return;
    }

    for (const k of filtered) {
        const status = getKeyStatus(k);
        const online = status === 'active' && isOnline(k);
        const lastUsed = getLastUsedStr(k);
        html += `<div class="table-row" data-id="${k.id}">
            <input type="checkbox" class="row-checkbox" value="${k.id}">
            <span class="key-cell">${k.key}</span>
            <span class="user-cell">${k.user ? (online ? '🟢 ' : '⚪ ') + k.user : '--'}</span>
            <span class="status-cell status-${status}">${status}</span>
            <span class="date-cell">${lastUsed}</span>
            <span class="date-cell">${k.expiresAt ? new Date(k.expiresAt).toLocaleDateString() : '--'}</span>
            <span class="action-cell">
                <button class="btn btn-sm edit-btn" data-id="${k.id}">Edit</button>
                <button class="btn btn-sm toggle-btn" data-id="${k.id}">${status === 'revoked' ? 'Activate' : 'Revoke'}</button>
                <button class="btn btn-sm btn-danger del-btn" data-id="${k.id}">Del</button>
            </span>
        </div>`;
    }

    container.innerHTML = html;
    document.getElementById('selectAll').addEventListener('change', (e) => {
        container.querySelectorAll('.row-checkbox').forEach(cb => cb.checked = e.target.checked);
    });
    container.querySelectorAll('.edit-btn').forEach(b => b.addEventListener('click', () => openEditModal(b.dataset.id)));
    container.querySelectorAll('.toggle-btn').forEach(b => b.addEventListener('click', () => toggleKeyStatus(b.dataset.id)));
    container.querySelectorAll('.del-btn').forEach(b => b.addEventListener('click', () => deleteKey(b.dataset.id)));
}

function toggleKeyStatus(id) {
    const k = db.find(x => x.id === id);
    if (!k) return;
    k.status = k.status === 'revoked' ? 'active' : 'revoked';
    saveDB();
    renderManageTable();
    showToast(`Key ${k.status === 'revoked' ? 'revoked' : 'activated'}`, 'info');
}

function deleteKey(id) {
    const k = db.find(x => x.id === id);
    if (!k || !confirm(`Delete key?\n${k.key}`)) return;
    db = db.filter(x => x.id !== id);
    saveDB();
    renderManageTable();
    showToast('Key deleted', 'info');
}

function applyBulkAction() {
    const action = document.getElementById('bulkAction').value;
    if (!action) return showToast('Select an action', 'error');
    const checked = document.querySelectorAll('.row-checkbox:checked');
    if (!checked.length) return showToast('Select keys first', 'error');
    const ids = new Set(Array.from(checked).map(cb => cb.value));
    if (action === 'delete') {
        if (!confirm(`Delete ${ids.size} keys?`)) return;
        db = db.filter(k => !ids.has(k.id));
    } else if (action === 'activate') db.forEach(k => { if (ids.has(k.id)) k.status = 'active'; });
    else if (action === 'revoke') db.forEach(k => { if (ids.has(k.id)) k.status = 'revoked'; });
    saveDB();
    renderManageTable();
    showToast(`Applied ${action} to ${ids.size} keys`, 'success');
}

// ===== MODALS =====

function openEditModal(id) {
    const k = db.find(x => x.id === id);
    if (!k) return;
    editingKeyId = id;
    document.getElementById('editKeyInput').value = k.key;
    document.getElementById('editUser').value = k.user || '';
    document.getElementById('editStatus').value = k.status;
    const days = k.expiresAt ? Math.max(0, Math.round((k.expiresAt - Date.now()) / 86400000)) : 0;
    document.getElementById('editExpiry').value = Math.min(days, 365);
    document.getElementById('editModal').classList.add('open');
}

function saveEdit() {
    const k = db.find(x => x.id === editingKeyId);
    if (!k) return;
    k.user = document.getElementById('editUser').value.trim();
    k.status = document.getElementById('editStatus').value;
    const days = parseInt(document.getElementById('editExpiry').value) || 0;
    k.expiresAt = computeExpiry(days);
    saveDB();
    renderManageTable();
    closeModals();
    showToast('Key updated', 'success');
}

function openAddCustomModal() {
    document.getElementById('customKeyInput').value = '';
    document.getElementById('customUser').value = '';
    document.getElementById('customExpiry').value = '0';
    document.getElementById('customStatus').value = 'active';
    document.getElementById('addCustomModal').classList.add('open');
}

function saveCustomKey() {
    const keyStr = document.getElementById('customKeyInput').value.trim();
    if (!keyStr) return showToast('Enter a key', 'error');
    if (db.find(k => k.key === keyStr)) return showToast('Key already exists', 'error');
    db.push({
        id: generateId(), key: keyStr, serial: 0,
        user: document.getElementById('customUser').value.trim(),
        status: document.getElementById('customStatus').value,
        expiresAt: computeExpiry(parseInt(document.getElementById('customExpiry').value) || 0),
        createdAt: Date.now()
    });
    saveDB();
    renderManageTable();
    closeModals();
    showToast('Custom key added', 'success');
}

function closeModals() {
    document.querySelectorAll('.modal').forEach(m => m.classList.remove('open'));
}

// ===== VALIDATE =====

async function validateKey() {
    const input = document.getElementById('validateInput').value.trim();
    const result = document.getElementById('validateResult');
    if (!input) {
        result.className = 'validate-result invalid';
        result.textContent = 'Please enter a key.';
        return;
    }
    try {
        const urlKey = new URLSearchParams(window.location.search).get('key');
        if (urlKey && !input) document.getElementById('validateInput').value = urlKey;
    } catch {}

    const secret = getSecret();
    const parts = input.split('-');
    const sig = parts.pop();
    const baseKey = parts.join('-');
    if (!baseKey || !sig) {
        result.className = 'validate-result invalid';
        result.textContent = 'Invalid key format.';
        return;
    }
    const expectedSig = await hmacSign(baseKey, secret);
    if (sig !== expectedSig) {
        result.className = 'validate-result invalid';
        result.textContent = 'Invalid signature. Key is not authentic.';
        return;
    }
    const dbKey = db.find(k => k.key === input);
    if (dbKey && getKeyStatus(dbKey) === 'active') {
        dbKey.lastUsedAt = Date.now();
        dbKey.lastUsedIP = document.getElementById('validateInput').value ? 'web' : dbKey.lastUsedIP;
        saveDB();
    }

    let msg = 'Valid signature! ';
    if (dbKey) {
        const status = getKeyStatus(dbKey);
        if (status === 'revoked') msg += 'Key is REVOKED.';
        else if (status === 'expired') msg += 'Key is EXPIRED.';
        else msg += `Key is ACTIVE. User: ${dbKey.user || 'unassigned'}`;
        if (dbKey.lastUsedAt) {
            const daysAgo = Math.floor((Date.now() - dbKey.lastUsedAt) / 86400000);
            msg += ` | Last used: ${daysAgo === 0 ? 'Today' : daysAgo + 'd ago'}`;
        }
    } else {
        msg += 'Key not found in database (signature valid).';
    }
    result.className = 'validate-result valid';
    result.textContent = msg;
    renderManageTable();
}

// ===== API =====

async function handleApiRequest() {
    const params = new URLSearchParams(window.location.search);
    const key = params.get('key');
    const format = params.get('format');
    if (!key) return;

    if (format === 'json') {
        const secret = getSecret();
        const parts = key.split('-');
        const sig = parts.pop();
        const baseKey = parts.join('-');
        const expectedSig = await hmacSign(baseKey, secret);
        const sigValid = sig === expectedSig;
        const dbKey = db.find(k => k.key === key);
        const status = dbKey ? getKeyStatus(dbKey) : 'unknown';

        if (dbKey && status === 'active') {
            dbKey.lastUsedAt = Date.now();
            dbKey.lastUsedIP = 'api';
            saveDB();
        }

        const isGood = sigValid && status === 'active';
        const secretKey = getSecret();
        const authData = "PUBG-" + key + "-" + (dbKey && dbKey.lastUsedAt ? String(dbKey.lastUsedAt) : "0") + "-Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz9E";
        const token = await hmacSign(authData, secretKey);

        const response = {
            status: isGood,
            reason: isGood ? "" : (!sigValid ? "Invalid signature" : "Key " + status),
            data: isGood ? {
                token: token + key.substr(0,8),
                rng: Math.floor(Date.now() / 1000),
                modname: "NEXUS MOD MENU",
                mod_status: "Connected"
            } : null
        };

        document.body.innerHTML = '<pre style="background:#0a0e14;color:#e2e8f0;padding:2rem;font-family:monospace;font-size:0.9rem">' + JSON.stringify(response, null, 2) + '</pre>';
        return;
    }

    setTimeout(() => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        const vt = document.getElementById('validateTab');
        const vb = document.querySelector('[data-tab="validate"]');
        if (vt) vt.classList.add('active');
        if (vb) vb.classList.add('active');
        document.getElementById('validateInput').value = key;
        validateKey();
    }, 300);
}

function copyText(text, label) {
    navigator.clipboard.writeText(text).then(() => showToast(`${label} copied!`, 'success'));
}

function buildApiUrl(key) {
    return `https://kbinaana.github.io/keygen-panel/?key=${key}&format=json`;
}

async function apiTest() {
    const key = document.getElementById('apiTestInput').value.trim();
    if (!key) return showToast('Enter a key', 'error');
    const url = buildApiUrl(key);
    try {
        const res = await fetch(url);
        const data = await res.json();
        document.getElementById('apiTestResult').textContent = JSON.stringify(data, null, 2);
        document.getElementById('apiTestResult').style.display = 'block';
    } catch {
        document.getElementById('apiTestResult').textContent = 'Error fetching. Try again.';
        document.getElementById('apiTestResult').style.display = 'block';
    }
}

// ===== SETTINGS =====

function exportDb() {
    const blob = new Blob([JSON.stringify(db, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `keymaster_${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    showToast('Database exported', 'success');
}

function importDb() { document.getElementById('importFileInput').click(); }

function handleImport(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
        try {
            const data = JSON.parse(ev.target.result);
            if (!Array.isArray(data)) throw new Error('Invalid');
            const add = confirm(`Add ${data.length} keys to DB? Cancel to replace.`);
            db = add ? db.concat(data) : data;
            saveDB();
            renderManageTable();
            showToast(`Imported ${data.length} keys`, 'success');
        } catch { showToast('Invalid JSON file', 'error'); }
    };
    reader.readAsText(file);
}

function getPhpUrl() {
    return (document.getElementById('phpServerUrl').value || '').trim();
}

async function syncToPhp() {
    const url = getPhpUrl();
    if (!url) return showToast('Enter PHP server URL first', 'error');
    if (!db.length) return showToast('No keys to sync', 'error');
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret: getSecret(), keys: db })
        });
        const data = await res.json();
        if (data.status) {
            showToast('Synced ' + db.length + ' keys to server!', 'success');
        } else {
            showToast('Sync failed: ' + (data.reason || 'unknown'), 'error');
        }
    } catch (e) {
        showToast('Connection error: ' + e.message, 'error');
    }
}

async function testPhpConnection() {
    const url = getPhpUrl();
    if (!url) return showToast('Enter PHP server URL first', 'error');
    try {
        const baseUrl = url.replace(/\/[^/]*$/, '') + '/api.php';
        const testUrl = url.includes('?') ? url.split('?')[0] : url;
        const res = await fetch(testUrl + '?key=TEST&format=json');
        const data = await res.json();
        if (data && typeof data.status !== 'undefined') {
            showToast('Server connected! Response: ' + JSON.stringify(data).substring(0, 50), 'success');
        } else {
            showToast('Server responded but unexpected format', 'error');
        }
    } catch (e) {
        showToast('Connection error: ' + e.message, 'error');
    }
}

function clearAllKeys() {
    if (!db.length) return;
    if (!confirm('Delete ALL keys? This cannot be undone!')) return;
    if (!confirm('ARE YOU SURE?')) return;
    db = [];
    saveDB();
    renderManageTable();
    showToast('All keys deleted', 'info');
}

function updateStats() {
    const total = db.length;
    const active = db.filter(k => getKeyStatus(k) === 'active').length;
    const expired = db.filter(k => getKeyStatus(k) === 'expired').length;
    const revoked = db.filter(k => getKeyStatus(k) === 'revoked').length;
    const activeUsers = new Set(db.filter(k => getKeyStatus(k) === 'active' && k.user).map(k => k.user)).size;
    const onlineNow = new Set(db.filter(k => getKeyStatus(k) === 'active' && k.user && isOnline(k)).map(k => k.user)).size;
    const ucl = document.getElementById('userCountLabel');
    if (ucl) ucl.textContent = `👤 ${activeUsers} active users (${onlineNow} online)`;
    document.getElementById('msActive').textContent = active;
    document.getElementById('msExpired').textContent = expired;
    document.getElementById('msRevoked').textContent = revoked;
    const usersEl = document.getElementById('msUsers');
    if (usersEl) usersEl.textContent = activeUsers;
    document.getElementById('dbInfo').textContent = `${total} keys stored (${active} active, ${activeUsers} users, ${onlineNow} online)`;
}

// ===== EVENT LISTENERS =====

document.getElementById('generateBtn').addEventListener('click', generateKeys);
document.getElementById('saveKeysBtn').addEventListener('click', saveGeneratedKeys);
document.getElementById('copyAllBtn').addEventListener('click', copyAll);
document.getElementById('exportBtn').addEventListener('click', exportTxt);
document.getElementById('clearBtn').addEventListener('click', clearOutput);

document.getElementById('validateBtn').addEventListener('click', validateKey);
document.getElementById('validateInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') validateKey(); });

document.getElementById('saveSecretBtn').addEventListener('click', () => {
    const val = document.getElementById('secretKey').value.trim();
    if (val) { saveSecret(val); showToast('Secret saved!', 'success'); }
});

document.getElementById('randomSecretBtn').addEventListener('click', () => {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    const secret = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    document.getElementById('secretKey').value = secret;
    saveSecret(secret);
    showToast('Random secret generated and saved!', 'success');
});

document.getElementById('applyBulkBtn').addEventListener('click', applyBulkAction);
document.getElementById('addCustomBtn').addEventListener('click', openAddCustomModal);
document.getElementById('saveCustomBtn').addEventListener('click', saveCustomKey);
document.getElementById('saveEditBtn').addEventListener('click', saveEdit);
document.getElementById('exportDbBtn').addEventListener('click', exportDb);
document.getElementById('importDbBtn').addEventListener('click', importDb);
document.getElementById('importFileInput').addEventListener('change', handleImport);
document.getElementById('clearAllBtn').addEventListener('click', clearAllKeys);
document.getElementById('searchInput').addEventListener('input', renderManageTable);

document.getElementById('copyUrlExample').addEventListener('click', () => {
    copyText(document.getElementById('urlExample').textContent, 'URL');
});

document.getElementById('copyCurlBtn').addEventListener('click', () => {
    copyText(document.getElementById('curlExample').textContent, 'cURL');
});

document.getElementById('copyFetchBtn').addEventListener('click', () => {
    copyText(document.getElementById('fetchExample').textContent, 'Fetch');
});

document.getElementById('copyPythonBtn').addEventListener('click', () => {
    copyText(document.getElementById('pythonExample').textContent, 'Python');
});

document.getElementById('copyNodeBtn').addEventListener('click', () => {
    copyText(document.getElementById('nodeExample').textContent, 'Node.js');
});

document.getElementById('apiTestBtn').addEventListener('click', apiTest);
document.getElementById('apiTestInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') apiTest(); });

document.getElementById('syncToPhpBtn').addEventListener('click', syncToPhp);
document.getElementById('testPhpBtn').addEventListener('click', testPhpConnection);

document.querySelectorAll('.filter-pills .pill').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-pills .pill').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.dataset.filter;
        renderManageTable();
    });
});

document.querySelectorAll('.modal-close, .modal-close-btn').forEach(el => {
    el.addEventListener('click', closeModals);
});

document.querySelectorAll('.modal-backdrop').forEach(el => {
    el.addEventListener('click', closeModals);
});

document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        const tab = document.getElementById(btn.dataset.tab + 'Tab');
        if (tab) tab.classList.add('active');
    });
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeModals();
});

document.getElementById('secretKey').value = getSecret();
const savedUrl = localStorage.getItem('php_server_url');
if (savedUrl) document.getElementById('phpServerUrl').value = savedUrl;
document.getElementById('phpServerUrl').addEventListener('change', () => {
    localStorage.setItem('php_server_url', document.getElementById('phpServerUrl').value);
});

// ===== INIT =====

loadDB();
renderManageTable();
updateStats();
generateKeys();
handleApiRequest();
