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
    return substr(strtoupper(preg_replace('/[^A-Z0-9]/', '', hash_hmac('sha256', $data, $secret))), 0, 4);
}

function getKeyStatus($k) {
    if ($k['status'] === 'revoked') return 'revoked';
    if (!empty($k['expiresAt']) && time() * 1000 > $k['expiresAt']) return 'expired';
    return 'active';
}

// Parse URL path
$requestUri = $_SERVER['REQUEST_URI'];
$path = parse_url($requestUri, PHP_URL_PATH);
$path = rtrim($path, '/');

// Route: /api/validate
if (strpos($path, '/api/validate') !== false || strpos($path, '/validate') !== false) {
    $key = $_GET['key'] ?? '';
    $format = $_GET['format'] ?? '';

    if (empty($key)) {
        die(json_encode(['status' => false, 'reason' => 'No key provided']));
    }

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
        $dbKey['lastUsedAt'] = round(microtime(true) * 1000);
        foreach ($db as &$k) {
            if ($k['key'] === $key) { $k['lastUsedAt'] = $dbKey['lastUsedAt']; break; }
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

// Route: /api/sync (POST) - sync keys from KeyMaster panel
if (strpos($path, '/api/sync') !== false) {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        die(json_encode(['status' => false, 'reason' => 'POST required']));
    }
    $input = json_decode(file_get_contents('php://input'), true);
    $secret = $input['secret'] ?? '';
    $keys = $input['keys'] ?? [];

    if ($secret !== SECRET_KEY) {
        die(json_encode(['status' => false, 'reason' => 'Unauthorized']));
    }
    if (!is_array($keys)) {
        die(json_encode(['status' => false, 'reason' => 'Invalid data']));
    }

    saveDB($keys);
    echo json_encode(['status' => true, 'reason' => 'Synced ' . count($keys) . ' keys']);
    exit;
}

// Route: /api/key/add (POST)
if (strpos($path, '/api/key/add') !== false) {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        die(json_encode(['status' => false, 'reason' => 'POST required']));
    }
    $input = json_decode(file_get_contents('php://input'), true);
    $secret = $input['secret'] ?? '';
    $key = $input['key'] ?? '';

    if ($secret !== SECRET_KEY) {
        http_response_code(403);
        die(json_encode(['status' => false, 'reason' => 'Unauthorized']));
    }
    if (empty($key)) {
        die(json_encode(['status' => false, 'reason' => 'No key']));
    }

    $db = loadDB();
    foreach ($db as $k) {
        if ($k['key'] === $key) {
            die(json_encode(['status' => false, 'reason' => 'Key exists']));
        }
    }

    $expiryDays = intval($input['expiryDays'] ?? 0);
    $db[] = [
        'id' => uniqid(),
        'key' => $key,
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

// Default: status page
header('Content-Type: application/json');
echo json_encode([
    'status' => true,
    'message' => 'KeyMaster PHP API is running',
    'endpoints' => [
        'GET /api/validate?key=KEY&format=json' => 'Validate a key',
        'POST /api/sync' => 'Sync keys (JSON body: {secret, keys})',
        'POST /api/key/add' => 'Add a key (JSON body: {secret, key, user, expiryDays, status})'
    ]
]);
