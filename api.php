<?php
// api.php
// Simple REST API using db.php (PDO) and JWT-based auth (HS256).
// Routes are determined by ?action=... and HTTP method. Returns JSON.

require_once __DIR__ . '/db.php';
header('Content-Type: application/json; charset=utf-8');

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? null;

/**
 * Helpers
 */
function send_json($data, $status = 200) {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function get_json_body() {
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    return is_array($data) ? $data : [];
}

/* Simple base64url helpers for JWT */
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function base64url_decode($b64u) {
    $b64 = strtr($b64u, '-_', '+/');
    $pad = 4 - (strlen($b64) % 4);
    if ($pad < 4) $b64 .= str_repeat('=', $pad);
    return base64_decode($b64);
}

function jwt_encode(array $payload, $expSeconds = 604800) {
    $header = ['alg' => 'HS256', 'typ' => 'JWT'];
    $payload['exp'] = time() + $expSeconds;
    $header_b64 = base64url_encode(json_encode($header));
    $payload_b64 = base64url_encode(json_encode($payload));
    $sig = hash_hmac('sha256', "$header_b64.$payload_b64", JWT_SECRET, true);
    $sig_b64 = base64url_encode($sig);
    return "$header_b64.$payload_b64.$sig_b64";
}

function jwt_decode($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    list($h_b64, $p_b64, $s_b64) = $parts;
    $sig = base64url_decode($s_b64);
    $expected = hash_hmac('sha256', "$h_b64.$p_b64", JWT_SECRET, true);
    if (!hash_equals($expected, $sig)) return null;
    $payload = json_decode(base64url_decode($p_b64), true);
    if (!is_array($payload) || (isset($payload['exp']) && time() > $payload['exp'])) return null;
    return $payload;
}

function get_bearer_token() {
    $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['Authorization'] ?? null;
    if (!$hdr) return null;
    if (preg_match('/Bearer\s(\S+)/', $hdr, $m)) return $m[1];
    return null;
}

function auth_user() {
    $token = get_bearer_token();
    if (!$token) return null;
    $payload = jwt_decode($token);
    if (!$payload || !isset($payload['user_id'])) return null;
    return $payload;
}

/**
 * ROUTES
 *
 * Minimal routing by ?action=...
 *
 * Public:
 *  - action=signup (POST) -> {name,id_number,password}
 *  - action=login (POST)  -> {id_number,password}
 *
 * Protected (require Authorization: Bearer <token>):
 *  - action=get_user (GET)
 *  - action=add_tool (POST) -> {name,model,calibrate_due,tool_number}
 *  - action=list_tools (GET) -> optional ?q=, ?status=
 *  - action=update_tool (POST) -> {id,...}
 *  - action=delete_tool (POST) -> {id}
 *  - action=add_employee (POST) -> {name,id_number,password}
 *  - action=list_employees (GET)
 *  - action=borrow_tool (POST) -> {tool_id,borrower_id,due_date}
 *  - action=return_tool (POST) -> {borrow_id,condition_on_return,mark_damaged} 
 *  - action=list_logs (GET) -> optional ?limit=, ?q=
 *  - action=calibrate_tool (POST) -> {tool_id,next_due_date,notes}
 *  - action=import_csv (POST multipart form, file field 'csv_file')
 */

// Input normalization
$pdo = getPDO();

try {
    switch ($action) {
        //
        // PUBLIC: signup
        //
        case 'signup':
            if ($method !== 'POST') send_json(['error' => 'Method not allowed'], 405);
            $data = get_json_body();
            $name = trim($data['name'] ?? '');
            $id_number = trim($data['id_number'] ?? '');
            $password = $data['password'] ?? '';
            if ($name === '' || $id_number === '' || $password === '') {
                send_json(['error' => 'name, id_number and password required'], 400);
            }
            // check unique id_number
            $stmt = $pdo->prepare("SELECT id FROM users WHERE id_number = ? LIMIT 1");
            $stmt->execute([$id_number]);
            if ($stmt->fetch()) send_json(['error' => 'id_number already exists'], 409);
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO users (name,id_number,password_hash,role,created_at) VALUES (?, ?, ?, 'employee', NOW())");
            $stmt->execute([$name, $id_number, $hash]);
            $userId = $pdo->lastInsertId();
            send_json(['success' => true, 'user_id' => (int)$userId], 201);
            break;

        //
        // PUBLIC: login
        //
        case 'login':
            if ($method !== 'POST') send_json(['error' => 'Method not allowed'], 405);
            $data = get_json_body();
            $id_number = trim($data['id_number'] ?? '');
            $password = $data['password'] ?? '';
            if ($id_number === '' || $password === '') send_json(['error' => 'id_number and password required'], 400);
            $stmt = $pdo->prepare("SELECT id,name,password_hash,role FROM users WHERE id_number = ? AND deleted_at IS NULL LIMIT 1");
            $stmt->execute([$id_number]);
            $user = $stmt->fetch();
            if (!$user || !password_verify($password, $user['password_hash'])) {
                send_json(['error' => 'invalid credentials'], 401);
            }
            $payload = [
                'user_id' => (int)$user['id'],
                'name' => $user['name'],
                'role' => $user['role']
            ];
            $token = jwt_encode($payload, 7 * 24 * 3600); // 7 days
            send_json(['token' => $token, 'user' => $payload]);
            break;

        //
        // AUTH REQUIRED: get_user
        //
        case 'get_user':
            $u = auth_user();
            if (!$u) send_json(['error' => 'Unauthorized'], 401);
            // return user details from DB
            $stmt = $pdo->prepare("SELECT id,name,id_number,role,email,created_at FROM users WHERE id = ? LIMIT 1");
            $stmt->execute([$u['user_id']]);
            $user = $stmt->fetch();
            send_json(['user' => $user]);
            break;

        //
        // AUTH REQUIRED: add_tool
        //
        case 'add_tool':
            $u = auth_user(); if (!$u) send_json(['error' => 'Unauthorized'], 401);
            if ($method !== 'POST') send_json(['error' => 'Method not allowed'], 405);
            $data = get_json_body();
            $name = trim($data['name'] ?? '');
            if ($name === '') send_json(['error' => 'name required'], 400);
            $model = $data['model'] ?? null;
            $calibrate_due = $data['calibrate_due'] ?? null;
            $tool_number = trim($data['tool_number'] ?? '');
            $pdo->beginTransaction();
            $stmt = $pdo->prepare("INSERT INTO tools (name,model,calibrate_due_date,tool_number,created_at) VALUES (?, ?, ?, ?, NOW())");
            $stmt->execute([$name, $model, $calibrate_due ?: null, $tool_number ?: null]);
            $toolId = $pdo->lastInsertId();
            // if no tool_number provided, generate one based on id
            if (empty($tool_number)) {
                $auto = sprintf('T-%05d', $toolId);
                $stmt = $pdo->prepare("UPDATE tools SET tool_number = ?, barcode = ? WHERE id = ?");
                $stmt->execute([$auto, $auto, $toolId]);
            } else {
                // if barcode not set, set barcode = tool_number
                $stmt = $pdo->prepare("UPDATE tools SET barcode = COALESCE(barcode, ?) WHERE id = ?");
                $stmt->execute([$tool_number, $toolId]);
            }
            // insert initial log
            $stmt = $pdo->prepare("INSERT INTO logs (action_at,action,tool_id,performed_by,note) VALUES (NOW(),'import',?,?,?)");
            $stmt->execute([ $toolId, $u['user_id'], 'tool created via API' ]);
            $pdo->commit();
            send_json(['success' => true, 'tool_id' => (int)$toolId], 201);
            break;

        //
        // list_tools
        //
        case 'list_tools':
            $q = $_GET['q'] ?? null;
            $status = $_GET['status'] ?? null;
            $limit = min(100, (int)($_GET['limit'] ?? 100));
            $params = [];
            $sql = "SELECT id,name,model,tool_number,barcode,status,calibrate_due_date,last_calibrated_at,notes FROM tools WHERE deleted_at IS NULL";
            if ($status) {
                $sql .= " AND status = ?";
                $params[] = $status;
            }
            if ($q) {
                $sql .= " AND (name LIKE ? OR model LIKE ? OR tool_number LIKE ? OR barcode LIKE ?)";
                $like = "%$q%";
                $params[] = $like; $params[] = $like; $params[] = $like; $params[] = $like;
            }
            $sql .= " ORDER BY id DESC LIMIT ?";
            $params[] = $limit;
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $rows = $stmt->fetchAll();
            send_json(['tools' => $rows]);
            break;

        //
        // update_tool
        //
        case 'update_tool':
            $u = auth_user(); if (!$u) send_json(['error' => 'Unauthorized'], 401);
            if ($method !== 'POST') send_json(['error' => 'Method not allowed'], 405);
            $data = get_json_body();
            $id = (int)($data['id'] ?? 0); if (!$id) send_json(['error' => 'id required'], 400);
            $fields = [];
            $params = [];
            foreach (['name','model','calibrate_due_date','tool_number','barcode','status','notes'] as $f) {
                if (array_key_exists($f, $data)) {
                    $fields[] = "$f = ?";
                    $params[] = ($data[$f] === '' ? null : $data[$f]);
                }
            }
            if (empty($fields)) send_json(['error' => 'no fields to update'], 400);
            $params[] = $id;
            $sql = "UPDATE tools SET " . implode(',', $fields) . ", updated_at = NOW() WHERE id = ? AND deleted_at IS NULL";
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            // log
            $stmt = $pdo->prepare("INSERT INTO logs (action_at,action,tool_id,performed_by,note) VALUES (NOW(),'adjustment',?,?,'tool updated via API')");
            $stmt->execute([$id, $u['user_id']]);
            send_json(['success' => true]);
            break;

        //
        // delete_tool (soft delete)
        //
        case 'delete_tool':
            $u = auth_user(); if (!$u) send_json(['error' => 'Unauthorized'], 401);
            if ($method !== 'POST') send_json(['error' => 'Method not allowed'], 405);
            $data = get_json_body();
            $id = (int)($data['id'] ?? 0); if (!$id) send_json(['error' => 'id required'], 400);
            $stmt = $pdo->prepare("UPDATE tools SET deleted_at = NOW() WHERE id = ?");
            $stmt->execute([$id]);
            $stmt = $pdo->prepare("INSERT INTO logs (action_at,action,tool_id,performed_by,note) VALUES (NOW(),'delete',?,?,'tool soft-deleted')");
            $stmt->execute([$id, $u['user_id']]);
            send_json(['success' => true]);
            break;

        //
        // add_employee (admin-ish)
        //
        case 'add_employee':
            $u = auth_user(); if (!$u) send_json(['error' => 'Unauthorized'], 401);
            if ($method !== 'POST') send_json(['error' => 'Method not allowed'], 405);
            // Note: role checks omitted. Add check $u['role'] === 'admin' if desired.
            $data = get_json_body();
            $name = trim($data['name'] ?? '');
            $id_number = trim($data['id_number'] ?? '');
            $password = $data['password'] ?? '';
            if ($name === '' || $id_number === '' || $password === '') send_json(['error' => 'name,id_number,password required'], 400);
            $stmt = $pdo->prepare("SELECT id FROM users WHERE id_number = ? LIMIT 1"); $stmt->execute([$id_number]);
            if ($stmt->fetch()) send_json(['error' => 'id_number exists'], 409);
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO users (name,id_number,password_hash,role,created_at) VALUES (?, ?, ?, 'employee', NOW())");
            $stmt->execute([$name, $id_number, $hash]);
            $newId = $pdo->lastInsertId();
            send_json(['success' => true, 'user_id' => (int)$newId], 201);
            break;

        //
        // list_employees
        //
        case 'list_employees':
            $u = auth_user(); if (!$u) send_json(['error' => 'Unauthorized'], 401);
            $stmt = $pdo->query("SELECT id,name,id_number,role,created_at FROM users WHERE deleted_at IS NULL ORDER BY name ASC");
            $rows = $stmt->fetchAll();
            send_json(['employees' => $rows]);
            break;

        //
        // borrow_tool
        //
        case 'borrow_tool':
            $u = auth_user(); if (!$u) send_json(['error' => 'Unauthorized'], 401);
            if ($method !== 'POST') send_json(['error' => 'Method not allowed'], 405);
            $data = get_json_body();
            $tool_id = (int)($data['tool_id'] ?? 0);
            $borrower_id = (int)($data['borrower_id'] ?? 0);
            $due_date = $data['due_date'] ?? null;
            if (!$tool_id || !$borrower_id) send_json(['error' => 'tool_id and borrower_id required'], 400);
            // check tool available
            $pdo->beginTransaction();
            $stmt = $pdo->prepare("SELECT status FROM tools WHERE id = ? FOR UPDATE");
            $stmt->execute([$tool_id]);
            $tool = $stmt->fetch();
            if (!$tool) { $pdo->rollBack(); send_json(['error' => 'tool not found'], 404); }
            if ($tool['status'] !== 'available') { $pdo->rollBack(); send_json(['error' => 'tool not available'], 409); }
            // create borrow
            $stmt = $pdo->prepare("INSERT INTO borrows (tool_id,borrower_id,borrowed_by,borrow_date,due_date,status,created_at) VALUES (?, ?, ?, NOW(), ?, 'borrowed', NOW())");
            $stmt->execute([$tool_id, $borrower_id, $u['user_id'], $due_date ?: null]);
            $borrowId = $pdo->lastInsertId();
            // update tool
            $stmt = $pdo->prepare("UPDATE tools SET status = 'borrowed', updated_at = NOW() WHERE id = ?");
            $stmt->execute([$tool_id]);
            // insert log
            $stmt = $pdo->prepare("INSERT INTO logs (action_at,action,tool_id,user_id,performed_by,borrow_id,note) VALUES (NOW(),'borrow',?,?,?,?,?)");
            $stmt->execute([$tool_id, $borrower_id, $u['user_id'], $borrowId, 'borrow via API']);
            $pdo->commit();
            send_json(['success' => true, 'borrow_id' => (int)$borrowId], 201);
            break;

        //
        // return_tool
        //
        case 'return_tool':
            $u = auth_user(); if (!$u) send_json(['error' => 'Unauthorized'], 401);
            if ($method !== 'POST') send_json(['error' => 'Method not allowed'], 405);
            $data = get_json_body();
            $borrow_id = (int)($data['borrow_id'] ?? 0);
            if (!$borrow_id) send_json(['error' => 'borrow_id required'], 400);
            $mark_damaged = !empty($data['mark_damaged']);
            $condition_on_return = $data['condition_on_return'] ?? null;
            $pdo->beginTransaction();
            $stmt = $pdo->prepare("SELECT tool_id,status FROM borrows WHERE id = ? FOR UPDATE");
            $stmt->execute([$borrow_id]);
            $borrow = $stmt->fetch();
            if (!$borrow) { $pdo->rollBack(); send_json(['error' => 'borrow not found'], 404); }
            if ($borrow['status'] !== 'borrowed') { $pdo->rollBack(); send_json(['error' => 'already returned'], 409); }
            $tool_id = (int)$borrow['tool_id'];
            // update borrow
            $stmt = $pdo->prepare("UPDATE borrows SET returned_at = NOW(), returned_by = ?, status = 'returned', condition_on_return = ? WHERE id = ?");
            $stmt->execute([$u['user_id'], $condition_on_return, $borrow_id]);
            // update tool status
            $new_status = $mark_damaged ? 'damaged' : 'available';
            $stmt = $pdo->prepare("UPDATE tools SET status = ?, updated_at = NOW() WHERE id = ?");
            $stmt->execute([$new_status, $tool_id]);
            // log
            $stmt = $pdo->prepare("INSERT INTO logs (action_at,action,tool_id,user_id,performed_by,borrow_id,prev_status,new_status,note) VALUES (NOW(),'return',?,?,?,?,?,?,?)");
            // fetch prev_status quick
            $stmtPrev = $pdo->prepare("SELECT status FROM tools WHERE id = ?");
            $stmtPrev->execute([$tool_id]);
            $prev = $stmtPrev->fetchColumn() ?: null;
            $stmt->execute([$tool_id, null, $u['user_id'], $borrow_id, $prev, $new_status, $condition_on_return ?: 'returned via API']);
            $pdo->commit();
            send_json(['success' => true]);
            break;

        //
        // list_logs
        //
        case 'list_logs':
            $u = auth_user(); if (!$u) send_json(['error' => 'Unauthorized'], 401);
            $limit = min(1000, (int)($_GET['limit'] ?? 200));
            $q = $_GET['q'] ?? null;
            $sql = "SELECT l.*, t.name AS tool_name, u.name AS user_name, p.name AS performer_name
                    FROM logs l
                    LEFT JOIN tools t ON t.id = l.tool_id
                    LEFT JOIN users u ON u.id = l.user_id
                    LEFT JOIN users p ON p.id = l.performed_by
                    WHERE 1=1";
            $params = [];
            if ($q) {
                $sql .= " AND (l.note LIKE ? OR t.name LIKE ? OR u.name LIKE ?)";
                $like = "%$q%";
                $params[] = $like; $params[] = $like; $params[] = $like;
            }
            $sql .= " ORDER BY l.action_at DESC LIMIT ?";
            $params[] = $limit;
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            $rows = $stmt->fetchAll();
            send_json(['logs' => $rows]);
            break;

        //
        // calibrate_tool
        //
        case 'calibrate_tool':
            $u = auth_user(); if (!$u) send_json(['error' => 'Unauthorized'], 401);
            if ($method !== 'POST') send_json(['error' => 'Method not allowed'], 405);
            $data = get_json_body();
            $tool_id = (int)($data['tool_id'] ?? 0); if (!$tool_id) send_json(['error' => 'tool_id required'], 400);
            $next_due = $data['next_due_date'] ?? null;
            $notes = $data['notes'] ?? null;
            $pdo->beginTransaction();
            $stmt = $pdo->prepare("INSERT INTO calibrations (tool_id,performed_by,performed_at,next_due_date,notes,created_at) VALUES (?, ?, NOW(), ?, ?, NOW())");
            $stmt->execute([$tool_id, $u['user_id'], $next_due ?: null, $notes]);
            $stmt = $pdo->prepare("UPDATE tools SET last_calibrated_at = NOW(), calibrate_due_date = ?, updated_at = NOW() WHERE id = ?");
            $stmt->execute([$next_due ?: null, $tool_id]);
            $stmt = $pdo->prepare("INSERT INTO logs (action_at,action,tool_id,performed_by,note) VALUES (NOW(),'calibrate',?,?,'calibration recorded via API')");
            $stmt->execute([$tool_id, $u['user_id']]);
            $pdo->commit();
            send_json(['success' => true]);
            break;

        //
        // import_csv (multipart/form-data csv_file)
        //
        case 'import_csv':
            $u = auth_user(); if (!$u) send_json(['error' => 'Unauthorized'], 401);
            if ($method !== 'POST') send_json(['error' => 'Method not allowed'], 405);
            if (empty($_FILES['csv_file']) || $_FILES['csv_file']['error'] !== UPLOAD_ERR_OK) {
                send_json(['error' => 'csv_file required'], 400);
            }
            $tmp = $_FILES['csv_file']['tmp_name'];
            $filename = $_FILES['csv_file']['name'];
            $content = file_get_contents($tmp);
            $lines = array_map('trim', explode("\n", str_replace("\r\n", "\n", $content)));
            $header = null;
            $rowCount = 0;
            $errors = [];
            $imported = 0;
            $pdo->beginTransaction();
            foreach ($lines as $ln => $line) {
                if ($ln === 0) { // header
                    $header = str_getcsv($line);
                    // normalize header names
                    $header = array_map(function($h){ return strtolower(trim($h)); }, $header);
                    continue;
                }
                if ($line === '') continue;
                $rowCount++;
                $cols = str_getcsv($line);
                $row = [];
                foreach ($header as $i => $colName) {
                    $row[$colName] = $cols[$i] ?? null;
                }
                // required: name
                $name = trim($row['name'] ?? '');
                if ($name === '') {
                    $errors[] = ['row' => $rowCount, 'error' => 'name required'];
                    continue;
                }
                $model = $row['model'] ?? null;
                $calibrate_due = !empty($row['calibrate_due']) ? $row['calibrate_due'] : null;
                $tool_number = !empty($row['tool_number']) ? $row['tool_number'] : null;
                try {
                    $stmt = $pdo->prepare("INSERT INTO tools (name,model,calibrate_due_date,tool_number,created_at) VALUES (?, ?, ?, ?, NOW())");
                    $stmt->execute([$name, $model, $calibrate_due, $tool_number]);
                    $tid = $pdo->lastInsertId();
                    if (empty($tool_number)) {
                        $auto = sprintf('T-%05d', $tid);
                        $stmt = $pdo->prepare("UPDATE tools SET tool_number = ?, barcode = ? WHERE id = ?");
                        $stmt->execute([$auto, $auto, $tid]);
                    } else {
                        $stmt = $pdo->prepare("UPDATE tools SET barcode = COALESCE(barcode, ?) WHERE id = ?");
                        $stmt->execute([$tool_number, $tid]);
                    }
                    $imported++;
                } catch (Exception $e) {
                    $errors[] = ['row' => $rowCount, 'error' => $e->getMessage()];
                }
            }
            // record csv_imports
            $stmt = $pdo->prepare("INSERT INTO csv_imports (filename, imported_by, imported_at, row_count, errors) VALUES (?, ?, NOW(), ?, ?)");
            $stmt->execute([$filename, $u['user_id'], $rowCount, json_encode($errors)]);
            $pdo->commit();
            send_json(['success' => true, 'imported' => $imported, 'rows' => $rowCount, 'errors' => $errors]);
            break;

        //
        // fallback
        //
        default:
            send_json(['error' => 'unknown action', 'available' => [
                'signup','login','get_user','add_tool','list_tools','update_tool','delete_tool',
                'add_employee','list_employees','borrow_tool','return_tool','list_logs',
                'calibrate_tool','import_csv'
            ]], 400);
    }
} catch (PDOException $ex) {
    // don't expose internal errors in production
    send_json(['error' => 'database error', 'message' => $ex->getMessage()], 500);
} catch (Exception $ex) {
    send_json(['error' => 'server error', 'message' => $ex->getMessage()], 500);
}
