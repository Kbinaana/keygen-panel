const formatSelect = document.getElementById('format');
const countInput = document.getElementById('count');
const prefixInput = document.getElementById('prefix');
const generateBtn = document.getElementById('generateBtn');
const keyOutput = document.getElementById('keyOutput');
const keyCount = document.getElementById('keyCount');
const copyAllBtn = document.getElementById('copyAllBtn');
const clearBtn = document.getElementById('clearBtn');

function randomChar() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    return chars[Math.floor(Math.random() * chars.length)];
}

function generateKey(format, prefix) {
    let key = '';
    for (const ch of format) {
        if (ch === 'X') {
            key += randomChar();
        } else {
            key += ch;
        }
    }
    return prefix + key;
}

function generateKeys() {
    const format = formatSelect.value;
    const count = Math.min(Math.max(parseInt(countInput.value) || 1, 1), 100);
    const prefix = prefixInput.value.toUpperCase().trim();

    const keys = [];
    for (let i = 0; i < count; i++) {
        keys.push(generateKey(format, prefix));
    }

    keyOutput.value = keys.join('\n');
    keyCount.textContent = `${keys.length} keys generated`;
    copyAllBtn.disabled = false;
}

function copyAll() {
    if (!keyOutput.value) return;
    navigator.clipboard.writeText(keyOutput.value).then(() => {
        copyAllBtn.textContent = 'Copied!';
        setTimeout(() => { copyAllBtn.textContent = 'Copy All'; }, 2000);
    });
}

function clearOutput() {
    keyOutput.value = '';
    keyCount.textContent = '0 keys generated';
    copyAllBtn.disabled = true;
}

generateBtn.addEventListener('click', generateKeys);
copyAllBtn.addEventListener('click', copyAll);
clearBtn.addEventListener('click', clearOutput);

document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') {
        generateKeys();
    }
});

generateKeys();
