<?php
// KeyMaster PHP API - Single file solution
// Deploy this on 000webhost, InfinityFree, or any PHP hosting

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

define('SECRET_KEY', 'MyModLoaderSecretKey2024');
define('DB_FILE', __DIR__ . '/keys.json');

function loadDB() {
    if (!file_exists(DB_FILE)) return [];
    $data = json_decode(file_get_contents(DB_FILE), true);
    return is_array($data) ? $data : [];
}

function saveDB($db) {
    file_put_contents(DB_FILE, json_encode($db, JSON_PRETTY_PRINT));
}

function hmacSign($data, $secret) {
    $hash = strtoupper(hash_hmac('sha256', $data, $secret));
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $sig = '';
    for ($i = 0; $i < 4; $i++) {
        $chunk = substr($hash, $i * 8, 8);
        $val = hexdec($chunk);
        $sig .= $chars[$val % 36];
    }
    return $sig;
}

function getKeyStatus($k) {
    if ($k['status'] === 'revoked') return 'revoked';
    if (!empty($k['expiresAt']) && time() * 1000 > $k['expiresAt']) return 'expired';
    return 'active';
}

$key = $_GET['key'] ?? '';
$action = $_GET['action'] ?? '';

// Handle POST form-encoded (Java GameLoader)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['key'])) {
    $key = $_POST['key'];
    $gameName = $_POST['game'] ?? 'pubgm';
    $uuid = $_POST['serial'] ?? '';
    $deviceFp = $_POST['fp'] ?? '';
    $arch = $_POST['arch'] ?? '';

    $db = loadDB();
    $parts = explode('-', $key);
    $sig = array_pop($parts);
    $baseKey = implode('-', $parts);
    $expectedSig = hmacSign($baseKey, SECRET_KEY);
    $sigValid = ($sig === $expectedSig);

    $dbKey = null;
    foreach ($db as $k) {
        if ($k['key'] === $key) { $dbKey = $k; break; }
    }

    $status = $dbKey ? getKeyStatus($dbKey) : 'unknown';

    if ($dbKey && $status === 'active') {
        foreach ($db as &$k) {
            if ($k['key'] === $key) { $k['lastUsedAt'] = round(microtime(true) * 1000); break; }
        }
        saveDB($db);
    }

    $isGood = $sigValid && $status === 'active';
    $token = hash_hmac('sha256', $gameName . '-' . $key . '-' . $uuid . '-secret', 'secret');

    $expiry = $dbKey && !empty($dbKey['expiresAt'])
        ? (string)($dbKey['expiresAt'] / 1000)
        : (string)(time() + 365 * 86400);

    $response = [
        'status' => $isGood,
        'reason' => $isGood ? '' : (!$sigValid ? 'Invalid signature' : 'Key ' . $status),
        'data' => $isGood ? [
            'token' => $token,
            'EXP' => $expiry,
            'rng' => time()
        ] : null
    ];

    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}

// KEY VALIDATION - triggered if key param is present (GET)
if (!empty($key)) {
    $format = $_GET['format'] ?? '';

    $db = loadDB();
    $parts = explode('-', $key);
    $sig = array_pop($parts);
    $baseKey = implode('-', $parts);
    $expectedSig = hmacSign($baseKey, SECRET_KEY);
    $sigValid = ($sig === $expectedSig);

    $dbKey = null;
    foreach ($db as $k) {
        if ($k['key'] === $key) { $dbKey = $k; break; }
    }

    $status = $dbKey ? getKeyStatus($dbKey) : 'unknown';

    if ($dbKey && $status === 'active') {
        foreach ($db as &$k) {
            if ($k['key'] === $key) { $k['lastUsedAt'] = round(microtime(true) * 1000); break; }
        }
        saveDB($db);
    }

    $isGood = $sigValid && $status === 'active';
    $authData = "PUBG-" . $key . "-" . ($dbKey && isset($dbKey['lastUsedAt']) ? $dbKey['lastUsedAt'] : "0") . "-Vm8Lk7Uj2JmsjCPVPVjrLa7zgfx3uz9E";
    $token = hmacSign($authData, SECRET_KEY) . substr($key, 0, 8);

    $response = [
        'status' => $isGood,
        'reason' => $isGood ? '' : (!$sigValid ? 'Invalid signature' : 'Key ' . $status),
        'data' => $isGood ? [
            'token' => $token,
            'rng' => time(),
            'modname' => 'NEXUS MOD MENU',
            'mod_status' => 'Connected'
        ] : null
    ];

    if ($format === 'json') {
        header('Content-Type: application/json');
        echo json_encode($response);
    } elseif ($isGood) {
        echo 'OK';
    } else {
        echo 'Invalid key';
    }
    exit;
}

// POST ACTIONS - sync or add
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $secret = $input['secret'] ?? '';
    $action = $input['action'] ?? $action;

    if ($secret !== SECRET_KEY) {
        http_response_code(403);
        die(json_encode(['status' => false, 'reason' => 'Unauthorized']));
    }

    // SYNC keys
    if ($action === 'sync') {
        $keys = $input['keys'] ?? [];
        if (!is_array($keys)) {
            die(json_encode(['status' => false, 'reason' => 'Invalid data']));
        }
        saveDB($keys);
        echo json_encode(['status' => true, 'reason' => 'Synced ' . count($keys) . ' keys']);
        exit;
    }

    // ADD key
    if ($action === 'add') {
        $newKey = $input['key'] ?? '';
        if (empty($newKey)) {
            die(json_encode(['status' => false, 'reason' => 'No key']));
        }
        $db = loadDB();
        foreach ($db as $k) {
            if ($k['key'] === $newKey) {
                die(json_encode(['status' => false, 'reason' => 'Key exists']));
            }
        }
        $expiryDays = intval($input['expiryDays'] ?? 0);
        $db[] = [
            'id' => uniqid(),
            'key' => $newKey,
            'serial' => 0,
            'user' => $input['user'] ?? '',
            'status' => $input['status'] ?? 'active',
            'expiresAt' => $expiryDays > 0 ? (time() + $expiryDays * 86400) * 1000 : null,
            'createdAt' => round(microtime(true) * 1000),
            'lastUsedAt' => null
        ];
        saveDB($db);
        echo json_encode(['status' => true, 'reason' => 'Key added']);
        exit;
    }

    die(json_encode(['status' => false, 'reason' => 'Unknown action']));
}

// Default: status page
header('Content-Type: application/json');
echo json_encode([
    'status' => true,
    'message' => 'KeyMaster PHP API is running',
    'endpoints' => [
        'GET ?key=KEY&format=json' => 'Validate a key',
        'POST {action:sync, secret, keys}' => 'Sync keys',
        'POST {action:add, secret, key, user, expiryDays}' => 'Add a key'
    ]
]);
