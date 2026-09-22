'use strict';
const $ = id => document.getElementById(id);
const $$ = s => Array.from(document.querySelectorAll(s));
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const SECRET_KEY = 'MyModLoaderSecretKey2024';
const LS_DB = 'keygen_db', LS_SECRET = 'keygen_secret', LS_GH = 'keygen_gh_token';
const LS_PASS = 'keygen_pass_hash', LS_LOCK = 'keygen_lock_ms', LS_LOGS = 'keygen_logs';
const LS_AUTO = 'keygen_gh_auto';

let db = [], currentFilter = 'all', editingKeyId = null, genItems = [];

function getSecret(){ return localStorage.getItem(LS_SECRET) || SECRET_KEY; }
function saveSecret(v){ localStorage.setItem(LS_SECRET, v); }
function getGhToken(){ return localStorage.getItem(LS_GH) || ''; }
function saveGhToken(v){ localStorage.setItem(LS_GH, v); }
function getAutoPush(){ return localStorage.getItem(LS_AUTO) !== '0'; }
function setAutoPush(b){ localStorage.setItem(LS_AUTO, b ? '1' : '0'); }

function loadDB(){
    try { db = JSON.parse(localStorage.getItem(LS_DB)) || []; } catch { db = []; }
    if (!Array.isArray(db)) db = [];
}
function saveDB(){ localStorage.setItem(LS_DB, JSON.stringify(db)); updateAll(); schedulePush(); }
function logAll(after){ saveLogsAfter(after); }

function generateId(){ return Date.now().toString(36) + Math.random().toString(36).substring(2,6); }
function randomChar(){ return 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[Math.floor(Math.random()*36)]; }

async function hmacSign(data, secret){
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
    const h = await crypto.subtle.sign('HMAC', key, enc.encode(data));
    return btoa(String.fromCharCode(...new Uint8Array(h))).slice(0,4);
}

async function generateKey(format, prefix, serial, secret, expiryDays){
    let key = '';
    for (const ch of format) key += ch === 'X' ? randomChar() : ch;
    const serialStr = serial ? '-' + String(serial).padStart(4,'0') : '';
    const expiryStr = expiryDays > 0 ? '-' + expiryDays + 'D' : '';
    const baseKey = prefix + key + serialStr + expiryStr;
    return secret ? `${baseKey}-${await hmacSign(baseKey, secret)}` : baseKey;
}

function computeExpiry(days){ return days > 0 ? Date.now() + days*86400000 : null; }
function isExpired(k){ return k.expiresAt && Date.now() > k.expiresAt; }
function getKeyStatus(k){ return k.status === 'revoked' ? 'revoked' : isExpired(k) ? 'expired' : 'active'; }
function fmtDate(ms){ return ms ? new Date(ms).toLocaleDateString() : '--'; }
function fmtExpiry(ms){
    if (!ms) return 'Never';
    const d = ms - Date.now();
    if (d <= 0) return 'Expired';
    const day = Math.floor(d/86400000), hr = Math.floor((d%86400000)/3600000), mi = Math.floor((d%3600000)/60000);
    if (day > 0) return day + 'd ' + hr + 'h left';
    if (hr > 0) return hr + 'h ' + mi + 'm left';
    return mi + 'm left';
}
function timeAgo(ms){
    const d = Math.max(0, Date.now() - ms);
    if (d < 60000) return 'just now';
    if (d < 3600000) return Math.floor(d/60000) + 'm ago';
    if (d < 86400000) return Math.floor(d/3600000) + 'h ago';
    return Math.floor(d/86400000) + 'd ago';
}

/* ===== Toast ===== */
function toast(msg, type){
    const t = $('toast');
    t.textContent = msg;
    t.className = 'toast show ' + (type || 'info');
    clearTimeout(t._h);
    t._h = setTimeout(() => { t.className = 'toast'; }, 3200);
}
async function copyText(txt){
    try {
        await navigator.clipboard.writeText(txt);
        toast('Copied!', 'success');
    } catch {
        const ta = document.createElement('textarea');
        ta.value = txt; document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); toast('Copied!', 'success'); } catch { toast('Copy failed', 'error'); }
        ta.remove();
    }
}

/* ===== Logs ===== */
function addLog(icon, txt){
    let logs = [];
    try { logs = JSON.parse(localStorage.getItem(LS_LOGS)) || []; } catch {}
    logs.unshift({ icon: icon, txt: txt, t: Date.now() });
    if (logs.length > 200) logs = logs.slice(0, 200);
    localStorage.setItem(LS_LOGS, JSON.stringify(logs));
}
function saveLogsAfter(view){ if (view === 'logs') renderLogs(); }

/* ===== Security / Lock ===== */
async function sha256(str){
    const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2,'0')).join('');
}
function getPassHash(){ return localStorage.getItem(LS_PASS) || ''; }
function getLockMs(){ const v = parseInt(localStorage.getItem(LS_LOCK)); return isNaN(v) ? 15 : v; }
let lastActivity = Date.now();
function touch(){ lastActivity = Date.now(); }
['click','keydown','touchstart','mousemove'].forEach(ev => document.addEventListener(ev, touch, {passive:true}));

async function initAuth(){
    if (!getPassHash()){
        showSetupPassword();
    } else {
        show('lockScreen'); $('lockTitle').textContent = 'Welcome back';
        $('lockPass').value = ''; $('lockErr').textContent = '';
        $('lockPass').focus();
    }
}
function showSetupPassword(){
    show('lockScreen'); $('lockTitle').textContent = 'Setup Admin Password';
    $('lockSub').textContent = 'First run — create a strong password (min 4 chars)';
    $('lockErr').innerHTML = '<button class="btn btn-sm" id="useDefaultBtn" style="margin-top:4px">Skip / Use default</button>';
    $('lockSubmit').textContent = 'Create Password';
    $('lockSubmit').onclick = async () => {
        const p = $('lockPass').value;
        if (p.length < 4){ $('lockErr').textContent = 'Minimum 4 characters'; shakeLock(); return; }
        localStorage.setItem(LS_PASS, await sha256(p));
        addLog('🔐','Panel password created');
        unlock();
    };
    $('useDefaultBtn').onclick = async () => {
        localStorage.setItem(LS_PASS, await sha256('admin'));
        addLog('🔐','Panel password set to default');
        toast('Default password: admin (change it in Settings)', 'warn');
        unlock();
    };
}
function shakeLock(){
    const c = $('lockScreen').querySelector('.lock-card');
    c.classList.add('shake'); setTimeout(() => c.classList.remove('shake'), 400);
}
async function doUnlock(){
    const p = $('lockPass').value;
    if ((await sha256(p)) === getPassHash()){
        unlock();
    } else {
        $('lockErr').textContent = 'Wrong password';
        shakeLock(); $('lockPass').value = ''; $('lockPass').focus();
        addLog('⚠','Failed unlock attempt');
    }
}
function unlock(){
    hide('lockScreen'); show('app'); lastActivity = Date.now();
}
function lockNow(){
    hide('app'); show('lockScreen');
    $('lockTitle').textContent = 'Panel Locked'; $('lockSub').textContent = 'Admin access required';
    $('lockPass').value = ''; $('lockErr').textContent = '';
    $('lockSubmit').textContent = 'Unlock'; $('lockSubmit').onclick = doUnlock;
    $('lockPass').addEventListener('keydown', e => { if (e.key === 'Enter') doUnlock(); });
}
setInterval(() => {
    const ms = getLockMs();
    if (ms > 0 && Date.now() - lastActivity > ms * 60000){
        addLog('🔒','Auto-locked after inactivity');
        lockNow();
    }
}, 30000);

function show(id){ $(id).classList.remove('hidden'); }
function hide(id){ $(id).classList.add('hidden'); }

/* ===== GitHub sync ===== */
function ghRepo(){
    let owner = 'kbinaana', repo = 'keygen-panel';
    try {
        const host = location.hostname.split('.')[0];
        if (host) owner = host;
        const seg = location.pathname.replace(/^\/+|\/+$/g,'').split('/');
        if (seg.length && seg[0]) repo = seg[0];
    } catch(e){}
    return {owner: owner, repo: repo};
}
function loaderUrl(){ return 'https://raw.githubusercontent.com/' + ghRepo().owner + '/' + ghRepo().repo + '/main/db.json'; }
function setGhStatus(msg, ok){
    const el = $('ghStatus'); if (!el) return;
    el.textContent = msg;
    el.style.color = ok === true ? 'var(--green)' : ok === false ? 'var(--red)' : 'var(--muted)';
    $('syncTitle').textContent = 'GitHub Sync';
    $('syncMeta').textContent = msg;
    $('syncDot').className = 'sync-dot' + (ok === true ? ' ok' : ok === false ? ' err' : '');
}
let pushTimer = null;
function schedulePush(){
    if (!getAutoPush()) return;
    const token = getGhToken();
    if (!token) return;
    clearTimeout(pushTimer);
    setGhStatus('Sync queued...');
    pushTimer = setTimeout(pushDbToGithub, 4000);
}
function b64EncodeUnicode(str){ return btoa(unescape(encodeURIComponent(str))); }
async function pushDbToGithub(){
    const token = getGhToken();
    if (!token){ setGhStatus('Token not set', false); return; }
    const repo = ghRepo();
    const content = b64EncodeUnicode(JSON.stringify(db, null, 2));
    const body = { message: 'Auto sync db.json', content: content };
    try {
        const getRes = await fetch('https://api.github.com/repos/' + repo.owner + '/' + repo.repo + '/contents/db.json', {
            headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json' }});
        if (getRes.ok){ const meta = await getRes.json(); body.sha = meta.sha; }
    } catch(e){}
    try {
        const putRes = await fetch('https://api.github.com/repos/' + repo.owner + '/' + repo.repo + '/contents/db.json', {
            method: 'PUT',
            headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (putRes.ok){
            const d = new Date();
            const msg = 'Synced ' + db.length + ' keys (' + d.toLocaleTimeString() + ')';
            setGhStatus(msg, true);
            addLog('☁', msg);
        } else {
            let reason = 'HTTP ' + putRes.status;
            try { const j = await putRes.json(); if (j && j.message) reason = j.message; } catch(e2){}
            setGhStatus('GitHub failed: ' + reason, false);
            addLog('✖','GitHub push failed: ' + reason);
        }
    } catch(e){
        setGhStatus('GitHub failed: ' + e.message, false);
        addLog('✖','GitHub push error: ' + e.message);
    }
}
async function testGhToken(){
    const token = getGhToken();
    if (!token){ toast('Save a token first', 'error'); return; }
    toast('Testing token...');
    try {
        const r = await fetch('https://api.github.com/user', { headers: { Authorization: 'Bearer ' + token }});
        if (r.ok){
            const me = await r.json();
            const chk = await fetch('https://api.github.com/repos/' + ghRepo().owner + '/' + ghRepo().repo, { headers: { Authorization: 'Bearer ' + token }});
            toast('Token OK — ' + me.login + (chk.ok ? '' : ' (repo access?)'), 'success');
            setGhStatus('Token OK as ' + me.login, true);
        } else {
            toast('Token invalid (HTTP ' + r.status + ')', 'error');
            setGhStatus('Token rejected', false);
        }
    } catch(e){ toast('Test error: ' + e.message, 'error'); }
}

/* ===== Rendering / helpers ===== */
function updateAll(){ updateStats(); renderKeys(); renderLogs(); renderDashboard(); renderSetup(); }

function updateStats(){
    const t = db.length;
    const active = db.filter(k => getKeyStatus(k) === 'active').length;
    const expired = db.filter(k => getKeyStatus(k) === 'expired').length;
    const revoked = db.filter(k => getKeyStatus(k) === 'revoked').length;
    $('stTotal').textContent = t; $('stActive').textContent = active;
    $('stExpired').textContent = expired; $('stRevoked').textContent = revoked;
    $('navKeyCount').textContent = t;
    $('keysMeta').textContent = t + ' keys · ' + active + ' active';
}

function renderSetup(){
    const items = [];
    items.push(getPassHash() ? ['st','✔','Admin password set'] : ['sf','!','Create admin password']);
    items.push(getGhToken() ? ['st','✔','GitHub token saved'] : ['sf','!','Save GitHub token in Settings']);
    const repo = ghRepo();
    items.push(['st','✔','Loader URL: ' + loaderUrl()]);
    $('setupList').innerHTML = items.map(([c,i,t]) =>
        '<div class="setup-item"><span class="' + c + '">' + i + '</span><span>' + esc(t) + '</span></div>').join('');
}

function renderDashboard(){
    const users = {};
    db.forEach(k => { if (k.user) users[k.user] = (users[k.user]||0) + (getKeyStatus(k)==='active'?1:0); });
    const uv = Object.entries(users).sort((a,b) => b[1]-a[1]);
    $('dashUsers').innerHTML = uv.length
        ? '<ul class="feed">' + uv.map(([u,c]) =>
            '<li><span class="f-ico">👤</span><span>' + esc(u) + '</span><span class="f-time">' + c + ' key' + (c>1?'s':'') + '</span></li>').join('') + '</ul>'
        : '<div class="list-zero muted">No users yet</div>';

    let logs = [];
    try { logs = JSON.parse(localStorage.getItem(LS_LOGS)) || []; } catch {}
    logs = logs.slice(0, 8);
    $('dashRecent').innerHTML = logs.length
        ? '<ul class="feed">' + logs.map(l =>
            '<li><span class="f-ico">' + esc(l.icon) + '</span><span>' + esc(l.txt) + '</span><span class="f-time">' + timeAgo(l.t) + '</span></li>').join('') + '</ul>'
        : '<div class="list-zero muted">No activity</div>';
}

function renderKeys(){
    const t = $('keySearch').value.trim().toLowerCase();
    let list = db;
    if (currentFilter !== 'all') list = list.filter(k => getKeyStatus(k) === currentFilter);
    if (t) list = list.filter(k => (k.user||'').toLowerCase().includes(t) || k.key.toLowerCase().includes(t));
    const rows = $('keyRows');
    if (!list.length){
        rows.innerHTML = '<div class="table-row" style="text-align:center;color:var(--muted);min-width:720px;justify-content:center">No keys found.</div>';
        return;
    }
    rows.innerHTML = list.map(k => {
        const st = getKeyStatus(k);
        const sel = $('selectAll') && $('selectAll').checked;
        return '<div class="table-row" data-id="' + esc(k.id) + '">' +
            '<input type="checkbox" class="row-check" value="' + esc(k.id) + '">' +
            '<span class="key-cell"><button class="key-copy" data-copy="' + esc(k.key) + '">⧉</button>' + esc(k.key) + '</span>' +
            '<span class="user-cell">' + (k.user ? esc(k.user) : '—') + '</span>' +
            '<span><span class="status-badge st-' + st + '">' + st + '</span></span>' +
            '<span class="exp-cell"><b>' + fmtDate(k.expiresAt) + '</b><br>' + fmtExpiry(k.expiresAt) + '</span>' +
            '<span class="row-actions">' +
                '<button class="btn btn-sm edit-btn" data-id="' + esc(k.id) + '">Edit</button>' +
                '<button class="btn btn-sm renew-btn" data-id="' + esc(k.id) + '">Renew</button>' +
                '<button class="btn btn-sm ' + (st==='revoked'?'':'') + ' tg-btn" data-id="' + esc(k.id) + '">' + (st==='revoked'?'Activate':'Revoke') + '</button>' +
                '<button class="btn btn-sm btn-danger del-btn" data-id="' + esc(k.id) + '">Del</button>' +
            '</span></div>';
    }).join('');

    rows.querySelectorAll('.key-copy').forEach(b => b.addEventListener('click', () => copyText(b.dataset.copy)));
    rows.querySelectorAll('.edit-btn').forEach(b => b.addEventListener('click', () => openEdit(b.dataset.id)));
    rows.querySelectorAll('.renew-btn').forEach(b => b.addEventListener('click', () => openRenew(b.dataset.id)));
    rows.querySelectorAll('.tg-btn').forEach(b => b.addEventListener('click', () => toggleStatus(b.dataset.id)));
    rows.querySelectorAll('.del-btn').forEach(b => b.addEventListener('click', () => confirmDelete(b.dataset.id)));
    rows.querySelectorAll('.row-check').forEach(c => c.addEventListener('change', updateSelCount));

    const first = db[0];
    $('copyActiveBtn').onclick = () => {
        const act = db.filter(k => getKeyStatus(k) === 'active').map(k => k.key);
        if (!act.length){ toast('No active keys', 'error'); return; }
        copyText(act.join('\n'));
    };
}

function updateSelCount(){
    const n = $$('#keyRows .row-check:checked').length;
    $('selCount').textContent = n ? n + ' selected' : '';
    $('bulkBar').classList.toggle('hidden', !n);
}

function getAllSelected(){
    return $$('#keyRows .row-check:checked').map(c => c.value);
}

/* ===== Key actions ===== */
function getKey(id){ return db.find(k => k.id === id); }

function openEdit(id){
    const k = getKey(id); editingKeyId = id;
    $('modalTitle').textContent = 'Edit Key';
    $('modalBody').innerHTML =
        '<label class="lbl">Key</label><input class="input" id="meKey" disabled value="' + esc(k.key) + '">' +
        '<label class="lbl">User</label><input class="input" id="meUser" value="' + esc(k.user||'') + '">' +
        '<label class="lbl">Status</label><select class="input" id="meStatus"><option value="active"' + (k.status==='active'?' selected':'') + '>Active</option><option value="revoked"' + (k.status==='revoked'?' selected':'') + '>Revoked</option></select>' +
        '<label class="lbl">Expiry (empty = never)</label><input class="input" id="meExp" type="datetime-local" value="' + (k.expiresAt ? toLocalInput(k.expiresAt) : '') + '">';
    showModal();
    $('modalOk').onclick = () => {
        k.user = $('meUser').value.trim();
        k.status = $('meStatus').value;
        const v = $('meExp').value;
        k.expiresAt = v ? new Date(v).getTime() : null;
        saveDB(); addLog('✎','Edited key ' + k.key); hideModal();
        toast('Key updated', 'success');
    };
}
function toLocalInput(ms){ const d = new Date(ms); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0,16); }

function openRenew(id){
    const k = getKey(id);
    $('modalTitle').textContent = 'Renew Key';
    $('modalBody').innerHTML =
        '<p class="muted" style="margin-bottom:10px">Current expiry: <b>' + (k.expiresAt ? fmtDate(k.expiresAt) : 'Never') + '</b></p>' +
        '<div class="chips" id="renewChips" style="margin-bottom:12px">' +
            [7,15,30,90,365].map(d => '<button class="chip" data-d="' + d + '">+' + d + 'd</button>').join('') + '</div>' +
        '<label class="lbl">Custom days</label><input class="input" id="renewCustom" type="number" min="1" value="">';
    showModal();
    let days = 30;
    $$('#renewChips .chip').forEach(c => c.addEventListener('click', () => {
        $$('#renewChips .chip').forEach(x => x.classList.remove('active')); c.classList.add('active'); days = parseInt(c.dataset.d);
    }));
    $('renewChips').querySelector('.chip').classList.add('active');
    $('modalOk').onclick = () => {
        const cst = parseInt($('renewCustom').value);
        if (cst > 0) days = cst;
        const base = k.expiresAt && k.expiresAt > Date.now() ? k.expiresAt : Date.now();
        k.expiresAt = base + days * 86400000;
        k.status = 'active';
        saveDB(); addLog('↻','Renewed ' + k.key + ' +' + days + 'd'); hideModal();
        toast('Key renewed +' + days + 'd', 'success');
    };
}

function toggleStatus(id){
    const k = getKey(id);
    k.status = k.status === 'revoked' ? 'active' : 'revoked';
    saveDB(); addLog(k.status === 'revoked' ? '✖' : '✔', (k.status==='revoked'?'Revoked':'Activated') + ' ' + k.key);
    toast(k.status === 'revoked' ? 'Key revoked — loader will drop it' : 'Key activated', k.status==='revoked' ? 'error' : 'success');
}

function confirmDelete(id){
    const k = getKey(id);
    confirmModal('Delete key?', 'This removes <code>' + esc(k.key) + '</code> permanently. Loader will reject it.', () => {
        db = db.filter(x => x.id !== id);
        saveDB(); addLog('🗑','Deleted key ' + k.key);
        toast('Key deleted', 'success');
    });
}

/* ===== Modals ===== */
function showModal(){ hide('confirm'); show('modal'); $('modalCancel').onclick = hideModal; $('modalX').onclick = hideModal; }
function hideModal(){ hide('modal'); $('modalBody').innerHTML = ''; }
function confirmModal(title, body, onYes){
    $('cfTitle').textContent = title;
    $('cfBody').innerHTML = body;
    show('confirm');
    $('cfCancel').onclick = () => hide('confirm');
    $('cfOk').onclick = () => { hide('confirm'); onYes(); };
    $('cfCancel').onclick = () => hide('confirm');
}

/* ===== Generate ===== */
const TEMPLATES = {
    nexus: { prefix:'NEXUS', format:'XXXXX-XXXXX-XXXXX' },
    pro:   { prefix:'PRO',   format:'XXXXX-XXXXX-XXXXX-XXXXX' },
    lite:  { prefix:'LITE',  format:'XXXXX-XXXX' },
    custom:{}
};
function applyTemplate(name){
    const t = TEMPLATES[name];
    if (name === 'custom') return;
    $('genPrefix').value = t.prefix;
    $('genFormat').value = t.format;
}
async function doGenerate(){
    const prefix = $('genPrefix').value.trim().toUpperCase();
    const format = $('genFormat').value.trim().toUpperCase();
    const count = Math.min(100, Math.max(1, parseInt($('genCount').value) || 1));
    const serial = Math.max(0, parseInt($('genSerial').value) || 0);
    const days = Math.max(0, Math.min(3650, parseInt($('genDays').value) || 0));
    const user = $('genUser').value.trim();
    const hmac = $('genHmac').checked;
    const secret = hmac ? $('genSecret').value.trim() || getSecret() : '';

    if (!prefix){ toast('Prefix required', 'error'); return; }
    if (!/^[A-Z0-9]+$/.test(prefix)){ toast('Prefix: A-Z / 0-9 only', 'error'); return; }
    if (!format || !/^[A-Z0-9X]+$/.test(format)){ toast('Format: X / A-Z / 0-9 only', 'error'); return; }
    if (!format.includes('X')){ toast('Format must contain X placeholders', 'error'); return; }

    $('genBtn').textContent = 'Generating...'; $('genBtn').disabled = true;
    try {
        genItems = [];
        for (let i = 0; i < count; i++){
            const s = serial > 0 ? serial + i : 0;
            const key = await generateKey(format, prefix, s, secret, days);
            genItems.push({ key, serial: s, user, days });
        }
        renderGenOutput();
        if ($('autoAdd').checked) addAllKeys();
        toast(count + ' key' + (count>1?'s':'') + ' generated', 'success');
    } finally {
        $('genBtn').textContent = '⚡ Generate Keys'; $('genBtn').disabled = false;
    }
}
function renderGenOutput(){
    $('genOutput').innerHTML = genItems.length
        ? genItems.map(g =>
            '<div class="gen-out-item"><span style="font-family:var(--mono);word-break:break-all">' + esc(g.key) + '</span>' +
            '<button class="key-copy" data-copy="' + esc(g.key) + '">⧉</button></div>').join('')
        : 'Generate keys to preview here…';
    $('genOutput').querySelectorAll('.key-copy').forEach(b => b.addEventListener('click', () => copyText(b.dataset.copy)));
}
function addAllKeys(){
    if (!genItems.length) return;
    genItems.forEach(g => {
        db.push({ id: generateId(), key: g.key, serial: g.serial, user: g.user || '', status: 'active', expiresAt: computeExpiry(g.days || 0), createdAt: Date.now() });
    });
    saveDB();
    addLog('✚','Added ' + genItems.length + ' keys to DB');
    toast('Added ' + genItems.length + ' keys', 'success');
    genItems = []; renderGenOutput();
}
function parseDays(key){
    const m = key.match(/-(\d+)D$/);
    return m ? parseInt(m[1], 10) : 0;
}

/* ===== Logs view ===== */
function renderLogs(){
    let logs = [];
    try { logs = JSON.parse(localStorage.getItem(LS_LOGS)) || []; } catch {}
    const t = $('logSearch') ? $('logSearch').value.trim().toLowerCase() : '';
    if (t) logs = logs.filter(l => (l.txt||'').toLowerCase().includes(t));
    $('logList').innerHTML = logs.length
        ? logs.map(l =>
            '<div class="log-item"><span class="log-ico">' + esc(l.icon) + '</span><span class="log-txt">' + esc(l.txt) + '</span><span class="log-time">' + timeAgo(l.t) + '</span></div>').join('')
        : 'No logs';
}

/* ===== Settings ===== */
function renderSettings(){
    $('setSecret').value = getSecret();
    $('ghToken').value = getGhToken();
    $('setLockMs').value = getLockMs();
    $('loaderUrl').textContent = loaderUrl();
}
function refreshSettings(){ renderSettings(); }

/* ===== View routing ===== */
function goView(name){
    $$('.view').forEach(v => v.classList.remove('active'));
    $('view-' + name).classList.add('active');
    $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.view === name));
    if (name === 'keys') renderKeys();
    if (name === 'logs') renderLogs();
    if (name === 'settings') renderSettings();
    if (name === 'dashboard') renderDashboard();
    touch();
}

/* ===== Save handlers ===== */
function saveTokenHandler(){
    const v = $('ghToken').value.trim();
    if (!v){ toast('Token empty', 'error'); return; }
    saveGhToken(v);
    setAutoPush(true);
    addLog('☁','GitHub token saved');
    setGhStatus('Token saved — pushing...');
    setTimeout(pushDbToGithub, 800);
    toast('Token saved', 'success');
}
function randSecret(){
    const arr = crypto.getRandomValues(new Uint8Array(24));
    const val = Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
    $('setSecret').value = val; saveSecret(val); refreshSecret();
    addLog('🔑','New HMAC secret generated');
    toast('New secret generated & saved', 'success');
}
function refreshSecret(){
    const el = $('setSecret'); el.type = 'password';
    el.value = getSecret();
}
function changePassword(){
    const p1 = $('setPass1').value, p2 = $('setPass2').value;
    if (p1.length < 4){ toast('Minimum 4 characters', 'error'); return; }
    if (p1 !== p2){ toast('Passwords do not match', 'error'); return; }
    sha256(p1).then(h => { localStorage.setItem(LS_PASS, h); addLog('🔐','Password changed'); toast('Password updated', 'success'); });
    $('setPass1').value = '';
    $('setPass2').value = '';
}
function saveLockHandler(){
    const v = Math.max(0, parseInt($('setLockMs').value) || 0);
    localStorage.setItem(LS_LOCK, v); toast('Auto-lock: ' + v + ' min', 'success');
}
function exportJSON(){
    const blob = new Blob([JSON.stringify(db, null, 2)], { type: 'application/json' });
    downloadBlob(blob, 'keygen_backup_' + Date.now() + '.json');
    addLog('⇩','Exported JSON backup');
}
function exportTXT(){
    const txt = db.map(k => k.key + (getKeyStatus(k)==='active' ? '' : ' (' + getKeyStatus(k) + ')')).join('\n');
    downloadBlob(new Blob([txt], { type:'text/plain' }), 'keys.txt');
    addLog('⇩','Exported TXT list');
}
function downloadBlob(blob, name){
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 3000);
}
function importJSON(file){
    const reader = new FileReader();
    reader.onload = () => {
        try {
            const data = JSON.parse(reader.result);
            if (!Array.isArray(data)) throw new Error('Not an array');
            const before = db.length;
            db = data; saveDB(); addLog('⇧','Imported ' + data.length + ' keys');
            toast('Imported ' + data.length + ' keys', 'success');
        } catch(e){ toast('Invalid JSON: ' + e.message, 'error'); }
    };
    reader.readAsText(file);
}

/* ===== Wipe ===== */
function wipeKeys(){
    confirmModal('Wipe all keys?', 'All ' + db.length + ' keys will be deleted from this panel.', () => {
        db = []; saveDB(); addLog('🗑','Wiped all keys');
        toast('All keys wiped', 'error');
    });
}
function fullReset(){
    confirmModal('Full reset?', 'Everything will be erased: keys, logs, password lock, token, settings.', () => {
        [LS_DB, LS_SECRET, LS_GH, LS_PASS, LS_LOCK, LS_LOGS, LS_AUTO].forEach(k => localStorage.removeItem(k));
        location.reload();
    });
}

/* ===== API mode (?key=&format=json) ===== */
async function handleApiMode(){
    const p = new URLSearchParams(location.search);
    const key = (p.get('key') || '').trim();
    const format = p.get('format');
    if (!key) return false;

    const secret = getSecret();
    let sigValid = false;
    if (key.includes('-')){
        const parts = key.split('-');
        if (parts.length >= 2){
            const expect = parts[parts.length - 1];
            const base = parts.slice(0, -1).join('-');
            try { sigValid = (await hmacSign(base, secret)) === expect; } catch(e){}
        }
    }
    let hasFormat = false;
    {
        const s = key;
        if (s.length >= 14 && s.length <= 60 && s.includes('-')){
            const ps = s.split('-');
            hasFormat = ps.length >= 3 && ps.every(pp => pp.length >= 4 && pp.length <= 20);
            if (hasFormat) for (const c of s) if (!/[A-Za-z0-9-]/.test(c)) { hasFormat = false; break; }
        }
    }
    const rec = db.find(r => (r.key || '').toLowerCase() === key.toLowerCase());
    let status = false, reason = 'Key not found', data = null;
    if (rec){
        const st = getKeyStatus(rec);
        if (st === 'revoked'){ reason = 'Key revoked'; }
        else if (st === 'expired'){ reason = 'Key expired'; }
        else {
            status = true; reason = 'Valid';
            data = { token: 'KEY_' + hashCode(key), rng: '', modname: 'NexusLoader', mod_status: 'active' };
        }
    }
    const result = { status: status, reason: reason, data: data };
    if (format === 'json'){
        document.body.innerHTML = '<pre style="font-family:monospace;padding:20px;color:#0f172a">' + esc(JSON.stringify(result, null, 2)) + '</pre>';
        addLog('🌐','API check for key ' + key.slice(0, 10) + '… → ' + (status ? 'valid' : reason));
        return true;
    }
    return false;
}

function hashCode(s){
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
    return h;
}

/* ===== Bind ===== */
function bind(){
    $$('.nav-item').forEach(n => n.addEventListener('click', () => goView(n.dataset.view)));
    $('lockSubmit').onclick = doUnlock;
    $('lockPass').addEventListener('keydown', e => { if (e.key === 'Enter') doUnlock(); });
    $('lockNowBtn').onclick = () => { addLog('🔒','Panel locked manually'); lockNow(); };

    $('keySearch').addEventListener('input', renderKeys);
    $('logSearch').addEventListener('input', renderLogs);
    $$('#filterChips .chip').forEach(c => c.addEventListener('click', () => {
        $$('#filterChips .chip').forEach(x => x.classList.remove('active')); c.classList.add('active');
        currentFilter = c.dataset.f; renderKeys();
    }));
    $('selectAll').addEventListener('change', function(){ $$('#keyRows .row-check').forEach(c => c.checked = this.checked); updateSelCount(); });
    $('bulkRevoke').onclick = bulkAction('revoked');
    $('bulkActivate').onclick = bulkAction('active');
    $('bulkDelete').onclick = bulkDelete;
    $('gotoGenerateBtn').onclick = () => goView('generate');
    $('dashPushBtn').onclick = pushDbToGithub;

    $$('#tplChips .chip').forEach(c => c.addEventListener('click', () => {
        $$('#tplChips .chip').forEach(x => x.classList.remove('active')); c.classList.add('active');
        applyTemplate(c.dataset.tpl);
    }));
    $('genBtn').onclick = doGenerate;
    $('genSecretEye').onclick = () => toggleEye($('genSecret'));
    $('copyAllBtn').onclick = () => { if (genItems.length) copyText(genItems.map(g=>g.key).join('\n')); else toast('Nothing to copy','error'); };
    $('addAllBtn').onclick = addAllKeys;

    $('setPassBtn').onclick = changePassword;
    $('setLockBtn').onclick = saveLockHandler;
    $('setSecretEye').onclick = () => toggleEye($('setSecret'));
    $('randSecretBtn').onclick = randSecret;
    $('resetSecretBtn').onclick = () => { saveSecret(SECRET_KEY); refreshSecret(); addLog('🔑','Secret reset to default'); toast('Secret reset to default','success'); };
    $('saveTokenBtn').onclick = saveTokenHandler;
    $('pushNowBtn').onclick = pushDbToGithub;
    $('ghTestBtn').onclick = testGhToken;
    $('ghTokenEye').onclick = () => toggleEye($('ghToken'));

    $('exportBtn').onclick = exportJSON;
    $('exportTxtBtn').onclick = exportTXT;
    $('importTrigger').onclick = () => $('importFile').click();
    $('importFile').addEventListener('change', e => { if (e.target.files[0]) importJSON(e.target.files[0]); e.target.value=''; });
    $('wipeKeysBtn').onclick = wipeKeys;
    $('resetAllBtn').onclick = fullReset;
    $('clearLogsBtn').onclick = () => { localStorage.setItem(LS_LOGS, '[]'); renderLogs(); toast('Logs cleared','success'); };
}
function bulkAction(status){
    return () => {
        const ids = getAllSelected();
        if (!ids.length) return;
        ids.forEach(id => { const k = getKey(id); if (k) k.status = status; });
        saveDB(); addLog('⚡','Bulk set ' + ids.length + ' keys → ' + status);
        toast('Applied to ' + ids.length + ' keys', 'success');
    };
}
function bulkDelete(){
    const ids = getAllSelected();
    if (!ids.length) return;
    confirmModal('Delete ' + ids.length + ' keys?', 'This will permanently remove the selected keys.', () => {
        db = db.filter(k => !ids.includes(k.id));
        saveDB(); addLog('🗑','Bulk deleted ' + ids.length + ' keys');
        toast('Deleted ' + ids.length + ' keys', 'error');
    });
}
function toggleEye(input){
    input.type = input.type === 'password' ? 'text' : 'password';
}

/* ===== Boot ===== */
async function boot(){
    loadDB();
    addLog('🚀','Panel opened');
    if (await handleApiMode()) return;
    bind();
    updateAll();
    renderSettings();
    if (!getPassHash()){ initAuth(); return; }
    lockNow();
    $('lockPass').focus();
}
document.addEventListener('DOMContentLoaded', boot);