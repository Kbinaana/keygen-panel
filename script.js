const SECRET_KEY = 'MyModLoaderSecretKey2024';

let db = [];
let currentFilter = 'all';
let editingKeyId = null;

function getSecret() {
    return localStorage.getItem('keygen_secret') || SECRET_KEY;
}

function saveSecret(val) {
    localStorage.setItem('keygen_secret', val);
}

// ============ DATABASE ============

function loadDB() {
    try {
        db = JSON.parse(localStorage.getItem('keygen_db')) || [];
    } catch { db = []; }
}

function saveDB() {
    localStorage.setItem('keygen_db', JSON.stringify(db));
    updateStats();
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substring(2, 6);
}

// ============ KEY HELPERS ============

function randomChar() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    return chars[Math.floor(Math.random() * chars.length)];
}

async function hmacSign(data, secret) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
    const hash = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let shortSig = '';
    for (let i = 0; i < 4; i++) {
        shortSig += chars[parseInt(hash.substring(i * 8, i * 8 + 8), 16) % 36];
    }
    return shortSig;
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

function computeExpiry(days) {
    if (!days || days <= 0) return null;
    return Date.now() + days * 86400000;
}

function isExpired(keyObj) {
    return keyObj.expiresAt && Date.now() > keyObj.expiresAt;
}

function getKeyStatus(keyObj) {
    if (keyObj.status === 'revoked') return 'revoked';
    if (isExpired(keyObj)) return 'expired';
    return 'active';
}

// ============ GENERATE TAB ============

async function generateKeys() {
    const format = document.getElementById('format').value;
    let count = Math.min(Math.max(parseInt(document.getElementById('count').value) || 1, 1), 500);
    const prefix = document.getElementById('prefix').value.toUpperCase().trim();
    const serialStart = parseInt(document.getElementById('serialStart').value) || 0;
    const expiryDays = parseInt(document.getElementById('expiry').value) || 0;
    const useHmac = document.getElementById('hmacToggle').checked;
    const secret = useHmac ? getSecret() : '';
    const assignUser = document.getElementById('assignUser').value.trim();

    const list = document.getElementById('keyList');
    list.innerHTML = '';
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
        div.addEventListener('click', () => copyKey(div, key));
        list.appendChild(div);
    });
}

function saveGeneratedKeys() {
    const btn = document.getElementById('saveKeysBtn');
    const items = btn._items || [];
    if (!items.length) return;
    for (const item of items) {
        db.push({
            id: generateId(),
            key: item.key,
            serial: item.serial,
            user: item.user || '',
            status: 'active',
            expiresAt: computeExpiry(item.expiryDays),
            createdAt: Date.now()
        });
    }
    saveDB();
    btn.textContent = 'Saved!';
    setTimeout(() => { btn.textContent = 'Save to Database'; }, 2000);
}

// ============ MANAGE TAB ============

function renderManageTable() {
    const container = document.getElementById('manageTable');
    const searchTerm = (document.getElementById('searchInput').value || '').toLowerCase();

    let filtered = [...db];

    if (currentFilter === 'active') filtered = filtered.filter(k => getKeyStatus(k) === 'active');
    else if (currentFilter === 'expired') filtered = filtered.filter(k => getKeyStatus(k) === 'expired');
    else if (currentFilter === 'revoked') filtered = filtered.filter(k => getKeyStatus(k) === 'revoked');

    if (searchTerm) {
        filtered = filtered.filter(k =>
            k.key.toLowerCase().includes(searchTerm) ||
            k.user.toLowerCase().includes(searchTerm) ||
            (k.serial && String(k.serial).includes(searchTerm))
        );
    }

    let html = `
        <div class="table-row header">
            <input type="checkbox" id="selectAll">
            <span>Key</span>
            <span class="hide-mobile">User</span>
            <span>Status</span>
            <span class="hide-mobile">Expiry</span>
            <span class="hide-mobile">Created</span>
            <span>Actions</span>
        </div>
    `;

    if (!filtered.length) {
        html += `<div class="table-row" style="grid-column:1/-1;text-align:center;padding:1.5rem;color:#484f58">No keys found.</div>`;
        container.innerHTML = html;
        return;
    }

    for (const k of filtered) {
        const status = getKeyStatus(k);
        const statusClass = `status-${status}`;
        const expiryStr = k.expiresAt ? new Date(k.expiresAt).toLocaleDateString() : '--';
        const createdStr = new Date(k.createdAt).toLocaleDateString();
        html += `
            <div class="table-row" data-id="${k.id}">
                <input type="checkbox" class="row-checkbox" value="${k.id}">
                <span class="key-cell">${k.key}</span>
                <span class="user-cell hide-mobile">${k.user || '--'}</span>
                <span class="status-cell ${statusClass}">${status}</span>
                <span class="date-cell hide-mobile">${expiryStr}</span>
                <span class="date-cell hide-mobile">${createdStr}</span>
                <span class="action-cell">
                    <button class="edit-btn" data-id="${k.id}">Edit</button>
                    <button class="toggle-btn" data-id="${k.id}">${status === 'revoked' ? 'Activate' : 'Revoke'}</button>
                    <button class="danger-btn del-btn" data-id="${k.id}">Del</button>
                </span>
            </div>
        `;
    }

    container.innerHTML = html;

    container.querySelector('.table-row.header').addEventListener('click', (e) => {
        if (e.target.id === 'selectAll') {
            const checked = e.target.checked;
            container.querySelectorAll('.row-checkbox').forEach(cb => cb.checked = checked);
        }
    });

    container.querySelectorAll('.edit-btn').forEach(btn => {
        btn.addEventListener('click', () => openEditModal(btn.dataset.id));
    });

    container.querySelectorAll('.toggle-btn').forEach(btn => {
        btn.addEventListener('click', () => toggleKeyStatus(btn.dataset.id));
    });

    container.querySelectorAll('.del-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteKey(btn.dataset.id));
    });

    document.getElementById('selectAll').addEventListener('change', (e) => {
        container.querySelectorAll('.row-checkbox').forEach(cb => cb.checked = e.target.checked);
    });
}

function toggleKeyStatus(id) {
    const k = db.find(x => x.id === id);
    if (!k) return;
    k.status = k.status === 'revoked' ? 'active' : 'revoked';
    saveDB();
    renderManageTable();
}

function deleteKey(id) {
    if (!confirm('Delete this key?')) return;
    db = db.filter(x => x.id !== id);
    saveDB();
    renderManageTable();
}

function applyBulkAction() {
    const action = document.getElementById('bulkAction').value;
    if (!action) return;
    const checked = document.querySelectorAll('.row-checkbox:checked');
    if (!checked.length) return alert('Select keys first.');
    const ids = new Set(Array.from(checked).map(cb => cb.value));
    if (action === 'delete') {
        if (!confirm(`Delete ${ids.size} keys?`)) return;
        db = db.filter(k => !ids.has(k.id));
    } else if (action === 'activate') {
        db.forEach(k => { if (ids.has(k.id)) k.status = 'active'; });
    } else if (action === 'revoke') {
        db.forEach(k => { if (ids.has(k.id)) k.status = 'revoked'; });
    }
    saveDB();
    renderManageTable();
}

// ============ MODAL ============

function openEditModal(id) {
    const k = db.find(x => x.id === id);
    if (!k) return;
    editingKeyId = id;
    document.getElementById('editKeyInput').value = k.key;
    document.getElementById('editUser').value = k.user || '';
    document.getElementById('editStatus').value = k.status;
    const days = k.expiresAt ? Math.round((k.expiresAt - Date.now()) / 86400000) : 0;
    document.getElementById('editExpiry').value = Math.max(0, days);
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
    document.getElementById('editModal').classList.remove('open');
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
    if (!keyStr) return alert('Enter a key.');
    const user = document.getElementById('customUser').value.trim();
    const days = parseInt(document.getElementById('customExpiry').value) || 0;
    const status = document.getElementById('customStatus').value;
    db.push({
        id: generateId(),
        key: keyStr,
        serial: 0,
        user,
        status,
        expiresAt: computeExpiry(days),
        createdAt: Date.now()
    });
    saveDB();
    renderManageTable();
    document.getElementById('addCustomModal').classList.remove('open');
}

// ============ VALIDATE ============

async function validateKey() {
    const input = document.getElementById('validateInput').value.trim();
    const result = document.getElementById('validateResult');
    if (!input) {
        result.className = 'invalid';
        result.textContent = 'Please enter a key.';
        result.style.display = 'block';
        return;
    }
    const secret = getSecret();
    const parts = input.split('-');
    const sig = parts.pop();
    const baseKey = parts.join('-');
    if (!baseKey || !sig) {
        result.className = 'invalid';
        result.textContent = 'Invalid key format.';
        result.style.display = 'block';
        return;
    }
    const expectedSig = await hmacSign(baseKey, secret);
    if (sig !== expectedSig) {
        result.className = 'invalid';
        result.textContent = 'Invalid signature. Key is not authentic.';
        result.style.display = 'block';
        return;
    }
    const dbKey = db.find(k => k.key === input);
    let msg = 'Valid signature! ';
    if (dbKey) {
        const status = getKeyStatus(dbKey);
        if (status === 'revoked') msg += 'Key is REVOKED.';
        else if (status === 'expired') msg += 'Key is EXPIRED.';
        else msg += `Key is ACTIVE. User: ${dbKey.user || 'unassigned'}`;
    } else {
        msg += 'Key not found in database.';
    }
    result.className = 'valid';
    result.textContent = msg;
    result.style.display = 'block';
}

// ============ HELPERS ============

function copyKey(el, key) {
    navigator.clipboard.writeText(key).then(() => {
        el.classList.add('copied');
        setTimeout(() => el.classList.remove('copied'), 1200);
    });
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

function clearOutput() {
    document.getElementById('keyList').innerHTML = '';
    document.getElementById('keyCount').textContent = '0 keys';
    document.getElementById('copyAllBtn').disabled = true;
    document.getElementById('exportBtn').disabled = true;
    document.getElementById('saveKeysBtn').disabled = true;
}

function updateStats() {
    const total = db.length;
    const active = db.filter(k => getKeyStatus(k) === 'active').length;
    const expired = db.filter(k => getKeyStatus(k) === 'expired').length;
    const revoked = db.filter(k => getKeyStatus(k) === 'revoked').length;
    document.getElementById('statTotal').textContent = total;
    document.getElementById('statActive').textContent = active;
    document.getElementById('statExpired').textContent = expired;
    document.getElementById('statRevoked').textContent = revoked;
    document.getElementById('dbInfo').textContent = `${total} keys stored (${active} active)`;
}

// ============ DATABASE EXPORT/IMPORT ============

function exportDb() {
    const blob = new Blob([JSON.stringify(db, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `keymaster_db_${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
}

function importDb() {
    document.getElementById('importFileInput').click();
}

function handleImport(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
        try {
            const data = JSON.parse(ev.target.result);
            if (!Array.isArray(data)) throw new Error('Invalid format');
            const add = confirm(`Add ${data.length} keys to existing database? Cancel to replace all.`);
            if (add) db = db.concat(data);
            else db = data;
            saveDB();
            renderManageTable();
            alert(`Imported ${data.length} keys.`);
        } catch {
            alert('Invalid JSON file.');
        }
    };
    reader.readAsText(file);
    e.target.value = '';
}

function clearAllKeys() {
    if (!db.length) return;
    if (!confirm('Delete ALL keys from database? This cannot be undone!')) return;
    if (!confirm('Are you sure?')) return;
    db = [];
    saveDB();
    renderManageTable();
}

// ============ EVENT LISTENERS ============

document.getElementById('generateBtn').addEventListener('click', generateKeys);
document.getElementById('saveKeysBtn').addEventListener('click', saveGeneratedKeys);
document.getElementById('copyAllBtn').addEventListener('click', copyAll);
document.getElementById('exportBtn').addEventListener('click', exportTxt);
document.getElementById('clearBtn').addEventListener('click', clearOutput);

document.getElementById('validateBtn').addEventListener('click', validateKey);
document.getElementById('validateInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') validateKey();
});

document.getElementById('saveSecretBtn').addEventListener('click', () => {
    const val = document.getElementById('secretKey').value.trim();
    if (val) { saveSecret(val); alert('Secret saved!'); }
});

document.getElementById('randomSecretBtn').addEventListener('click', () => {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    const secret = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    document.getElementById('secretKey').value = secret;
    saveSecret(secret);
    alert('Random secret generated and saved!');
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

document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.dataset.filter;
        renderManageTable();
    });
});

document.querySelectorAll('.close-modal').forEach(el => {
    el.addEventListener('click', () => {
        document.querySelectorAll('.modal').forEach(m => m.classList.remove('open'));
    });
});

window.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal')) e.target.classList.remove('open');
});

document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(btn.dataset.tab + 'Tab').classList.add('active');
    });
});

document.getElementById('secretKey').value = getSecret();

// ============ INIT ============

loadDB();
renderManageTable();
updateStats();
