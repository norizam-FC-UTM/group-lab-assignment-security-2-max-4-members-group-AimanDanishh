<?php
// ==========================================================
// SECJ3483 Web Technology
// Person BMI SECURE Slim Backend
// ==========================================================

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/db.php';

// ✅ FIX 5 (part): JWT secret key — store in environment variable, not hardcoded in production.
// Example: define via $_ENV['JWT_SECRET'] loaded from a .env file.
define('JWT_SECRET', $_ENV['JWT_SECRET'] ?? 'CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_IN_PRODUCTION');

$app = AppFactory::create();

// Required for JSON/form body parsing in Slim 4.
$app->addBodyParsingMiddleware();

// ✅ FIX 12 (part): Disable detailed error display for end-users.
// Set displayErrorDetails to false so stack traces are not sent to clients.
// Errors are still logged internally.
$displayErrors = false; // Set true only during local dev
$app->addErrorMiddleware($displayErrors, true, true);

// ----------------------------------------------------------
// CORS for Vue CLI frontend
// ----------------------------------------------------------
$app->add(function (Request $request, $handler) {
    if ($request->getMethod() === 'OPTIONS') {
        $response = new \Slim\Psr7\Response();
    } else {
        $response = $handler->handle($request);
    }

    // NOTE: In production, replace '*' with your actual frontend domain.
    // e.g. 'https://yourapp.example.com'
    return $response
        ->withHeader('Access-Control-Allow-Origin', '*')
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        ->withHeader('Access-Control-Allow-Credentials', 'false');
});

// ----------------------------------------------------------
// Helper functions
// ----------------------------------------------------------
function jsonResponse(Response $response, $data, int $status = 200): Response
{
    $response->getBody()->write(json_encode($data, JSON_PRETTY_PRINT));

    return $response
        ->withHeader('Content-Type', 'application/json')
        ->withStatus($status);
}

function getRequestData(Request $request): array
{
    $data = $request->getParsedBody();

    if (is_array($data) && !empty($data)) {
        return $data;
    }

    $rawBody = (string) $request->getBody();

    if ($rawBody !== '') {
        $jsonData = json_decode($rawBody, true);

        if (is_array($jsonData)) {
            return $jsonData;
        }
    }

    return is_array($data) ? $data : [];
}

// ✅ FIX 5: Real signed JWT creation with expiry — pure PHP, no external library.
// BEFORE: base64_encode(json_encode($payload)) — unsigned, editable, no expiry.
// AFTER:  HS256 JWT built manually using hash_hmac(); includes iat and exp (1 hour).
// The HMAC signature means any tampering with header or payload invalidates the token.
function base64UrlEncode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function createJwtToken(array $user): string
{
    $header  = base64UrlEncode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload = base64UrlEncode(json_encode([
        'user_id' => $user['id'],
        'role'    => $user['role'],
        'email'   => $user['email'],
        'iat'     => time(),
        'exp'     => time() + 3600  // expires in 1 hour
    ]));

    $signature = base64UrlEncode(
        hash_hmac('sha256', "$header.$payload", JWT_SECRET, true)
    );

    return "$header.$payload.$signature";
}

// ✅ FIX 6: Proper JWT verification on every protected route — pure PHP, no external library.
// BEFORE: Trusted an unsigned base64 blob; defaulted to user 1 when no token.
// AFTER:  Recomputes the HMAC signature and compares with hash_equals() (timing-safe).
//         Also checks the exp claim so expired tokens are rejected.
function verifyTokenFromRequest(Request $request): ?object
{
    $auth = $request->getHeaderLine('Authorization');

    if (!$auth || !preg_match('/Bearer\s+(\S+)/', $auth, $matches)) {
        return null;
    }

    $parts = explode('.', $matches[1]);
    if (count($parts) !== 3) {
        return null;
    }

    [$header, $payload, $signature] = $parts;

    // Recompute expected signature and compare timing-safely.
    $expected = base64UrlEncode(
        hash_hmac('sha256', "$header.$payload", JWT_SECRET, true)
    );

    if (!hash_equals($expected, $signature)) {
        return null; // Signature mismatch — token was tampered with.
    }

    $data = json_decode(base64_decode(strtr($payload, '-_', '+/')));

    if (!$data || !isset($data->exp) || time() > $data->exp) {
        return null; // Token expired or malformed.
    }

    return $data;
}

// ✅ FIX 2: BMI calculation at backend.
// BEFORE: bmi and category were accepted from the frontend (easily manipulated).
// AFTER:  Backend always calculates BMI and category — frontend values are ignored.
function calculateBmi(float $height, float $weight): float
{
    return round($weight / ($height * $height), 2);
}

function getBmiCategory(float $bmi): string
{
    if ($bmi < 18.5) return 'Underweight';
    if ($bmi < 25.0) return 'Normal';
    if ($bmi < 30.0) return 'Overweight';
    return 'Obese';
}

// ✅ FIX 12: Secure error handler — logs internally, returns generic message to client.
// BEFORE: exposeException() returned error message, file path, and line number to the API client.
// AFTER:  Error is logged with error_log(); client only sees a generic message.
function handleException(Response $response, \Throwable $e): Response
{
    error_log('[BMI-API ERROR] ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());

    return jsonResponse($response, [
        'error' => 'Unable to process request.'
    ], 500);
}

// ✅ FIX 1 (helper): Validation for BMI input fields.
// BEFORE: No validation — negative weights, zero heights, empty names were accepted.
// AFTER:  Returns a string error message if any rule fails, or null if all pass.
function validateBmiInput(array $data): ?string
{
    if (!isset($data['name']) || trim($data['name']) === '') {
        return 'Name is required.';
    }
    if (!isset($data['age']) || !is_numeric($data['age']) || $data['age'] < 1 || $data['age'] > 120) {
        return 'Age must be between 1 and 120.';
    }
    if (!isset($data['height']) || !is_numeric($data['height']) || $data['height'] < 0.5 || $data['height'] > 2.5) {
        return 'Height must be between 0.5 and 2.5 meters.';
    }
    if (!isset($data['weight']) || !is_numeric($data['weight']) || $data['weight'] < 2 || $data['weight'] > 300) {
        return 'Weight must be between 2 and 300 kg.';
    }
    return null;
}

// ----------------------------------------------------------
// Root routes
// ----------------------------------------------------------
$app->get('/', function (Request $request, Response $response) {
    return jsonResponse($response, [
        'message' => 'Person BMI Secure Slim Backend',
    ]);
});

$app->get('/api/health', function (Request $request, Response $response) {
    return jsonResponse($response, [
        'status' => 'ok',
        'api'    => 'person-bmi-secure-backend'
    ]);
});

// ----------------------------------------------------------
// Public route: Register
// ----------------------------------------------------------
$app->post('/api/register', function (Request $request, Response $response) {
    try {
        $pdo  = getPDO();
        $data = getRequestData($request);

        // ✅ FIX 1 (part): Basic input presence validation for registration.
        $name     = trim($data['name'] ?? '');
        $email    = trim($data['email'] ?? '');
        $password = $data['password'] ?? '';

        if ($name === '' || $email === '' || $password === '') {
            return jsonResponse($response, ['error' => 'Name, email, and password are required.'], 400);
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return jsonResponse($response, ['error' => 'Invalid email format.'], 400);
        }

        // ✅ FIX 3: Password hashing.
        // BEFORE: Password stored as plain text in both `password` and `password_hash` columns.
        // AFTER:  Only password_hash is stored, using PHP's password_hash() with PASSWORD_DEFAULT (bcrypt).
        //         The plain password is never saved to the database.
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        // ✅ FIX 4: Prepared statements to prevent SQL Injection.
        // BEFORE: $sql = "INSERT INTO users ... VALUES ('$name', '$email', '$password', '$role')";
        //         — user input is concatenated directly into SQL.
        // AFTER:  Named placeholders (:name, :email, etc.) separate SQL structure from data.
        //         The database driver handles escaping; injection is not possible.

        // Role is forced to 'user' — frontend cannot self-assign staff/admin.
        $stmt = $pdo->prepare(
            "INSERT INTO users (name, email, password_hash, role)
             VALUES (:name, :email, :password_hash, 'user')"
        );
        $stmt->execute([
            ':name'          => $name,
            ':email'         => $email,
            ':password_hash' => $passwordHash,
        ]);
        $id = $pdo->lastInsertId();

        // ✅ FIX 10: Return only safe fields — no password_hash in response.
        // BEFORE: SELECT * returned password and password_hash to the client.
        // AFTER:  Only id, name, email, role are fetched and returned.
        $stmt = $pdo->prepare('SELECT id, name, email, role FROM users WHERE id = ?');
        $stmt->execute([$id]);
        $user = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'Registration successful.',
            'user'    => $user
        ], 201);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// ----------------------------------------------------------
// Public route: Login
// ----------------------------------------------------------
$app->post('/api/login', function (Request $request, Response $response) {
    try {
        $pdo  = getPDO();
        $data = getRequestData($request);

        $email    = trim($data['email'] ?? '');
        $password = $data['password'] ?? '';

        // ✅ FIX 4: Prepared statement for login query.
        // BEFORE: $sql = "SELECT * FROM users WHERE email = '$email' AND password = '$password'";
        //         — classic SQL Injection point; e.g. email = "ali@x.com' --" bypassed the check.
        // AFTER:  Prepared statement; only email is used in the WHERE clause.
        //         Password is verified in PHP via password_verify(), not in SQL.
        $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?');
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        // ✅ FIX 3 (part): Verify password against stored hash.
        // BEFORE: Plain-text comparison inside the SQL query.
        // AFTER:  password_verify() safely compares the submitted password with the bcrypt hash.
        if (!$user || !password_verify($password, $user['password_hash'])) {
            return jsonResponse($response, ['error' => 'Invalid email or password.'], 401);
        }

        // ✅ FIX 5 (part): Issue a real signed JWT.
        $token = createJwtToken($user);

        // ✅ FIX 10 (part): Return only safe user fields — no password_hash.
        return jsonResponse($response, [
            'message' => 'Login successful.',
            'token'   => $token,
            'user'    => [
                'id'    => $user['id'],
                'name'  => $user['name'],
                'email' => $user['email'],
                'role'  => $user['role'],
            ]
        ]);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// ----------------------------------------------------------
// Protected route: Profile
// ----------------------------------------------------------
$app->get('/api/profile', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        // ✅ FIX 6: Verify JWT — reject if missing or invalid.
        // BEFORE: Defaulted to user 1 when no token was provided.
        // AFTER:  Returns 401 Unauthorized if the token is absent, expired, or tampered.
        $decoded = verifyTokenFromRequest($request);
        if (!$decoded) {
            return jsonResponse($response, ['error' => 'Unauthorized.'], 401);
        }

        $userId = $decoded->user_id;

        // ✅ FIX 4 + FIX 10: Prepared statement + safe field selection.
        $stmt = $pdo->prepare('SELECT id, name, email, role, created_at FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        return jsonResponse($response, ['user' => $user]);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// ----------------------------------------------------------
// BMI routes
// ----------------------------------------------------------

// GET /api/persons — returns only the authenticated user's own records.
$app->get('/api/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        // ✅ FIX 6: Require valid JWT.
        $decoded = verifyTokenFromRequest($request);
        if (!$decoded) {
            return jsonResponse($response, ['error' => 'Unauthorized.'], 401);
        }

        // ✅ FIX 7 (part): Owner-based access — always filter by the authenticated user's ID.
        // BEFORE: ?user_id= query param could override owner; no token required at all.
        // AFTER:  user_id comes from the verified JWT only; query params are ignored.
        $userId = $decoded->user_id;

        // ✅ FIX 4 + FIX 10: Prepared statement + safe columns only.
        $stmt = $pdo->prepare(
            'SELECT id, user_id, name, age, height, weight, bmi, category, notes, created_at
             FROM persons
             WHERE user_id = ?
             ORDER BY id DESC'
        );
        $stmt->execute([$userId]);
        $persons = $stmt->fetchAll();

        return jsonResponse($response, ['persons' => $persons]);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// POST /api/persons — create a new BMI record.
$app->post('/api/persons', function (Request $request, Response $response) {
    try {
        $pdo  = getPDO();
        $data = getRequestData($request);

        // ✅ FIX 6: Require valid JWT.
        $decoded = verifyTokenFromRequest($request);
        if (!$decoded) {
            return jsonResponse($response, ['error' => 'Unauthorized.'], 401);
        }

        // ✅ FIX 1: Backend validation for BMI data.
        // BEFORE: No validation — empty names, negative ages, zero heights were stored.
        // AFTER:  All business rules are enforced server-side before any DB write.
        $validationError = validateBmiInput($data);
        if ($validationError) {
            return jsonResponse($response, ['error' => $validationError], 400);
        }

        $name   = trim($data['name']);
        $age    = (int)   $data['age'];
        $height = (float) $data['height'];
        $weight = (float) $data['weight'];
        $notes  = trim($data['notes'] ?? '');

        // ✅ FIX 2: Backend BMI calculation.
        // BEFORE: bmi and category were taken from the frontend (easily manipulated).
        // AFTER:  Backend calculates bmi and category from height and weight; frontend values ignored.
        $bmi      = calculateBmi($height, $weight);
        $category = getBmiCategory($bmi);

        // ✅ FIX 7 (part): user_id is taken from the verified JWT, not from the request body.
        // BEFORE: $user_id = $data['user_id'] ?? 1  — frontend could claim any user ID.
        // AFTER:  $userId comes from $decoded->user_id which is cryptographically tied to the login.
        $userId = $decoded->user_id;

        // ✅ FIX 4: Prepared statement.
        $stmt = $pdo->prepare(
            'INSERT INTO persons (user_id, name, age, height, weight, bmi, category, notes)
             VALUES (:user_id, :name, :age, :height, :weight, :bmi, :category, :notes)'
        );
        $stmt->execute([
            ':user_id'  => $userId,
            ':name'     => $name,
            ':age'      => $age,
            ':height'   => $height,
            ':weight'   => $weight,
            ':bmi'      => $bmi,
            ':category' => $category,
            ':notes'    => $notes,
        ]);
        $id = $pdo->lastInsertId();

        // ✅ FIX 10: Safe field selection.
        $stmt = $pdo->prepare(
            'SELECT id, user_id, name, age, height, weight, bmi, category, notes, created_at
             FROM persons WHERE id = ?'
        );
        $stmt->execute([$id]);
        $person = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'BMI record created.',
            'person'  => $person
        ], 201);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// GET /api/persons/{id} — view a single record (owner, staff, or admin).
$app->get('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();

        // ✅ FIX 6: Require valid JWT.
        $decoded = verifyTokenFromRequest($request);
        if (!$decoded) {
            return jsonResponse($response, ['error' => 'Unauthorized.'], 401);
        }

        $id = (int) $args['id'];

        // ✅ FIX 4: Prepared statement.
        $stmt = $pdo->prepare(
            'SELECT id, user_id, name, age, height, weight, bmi, category, notes, created_at
             FROM persons WHERE id = ?'
        );
        $stmt->execute([$id]);
        $person = $stmt->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found.'], 404);
        }

        // ✅ FIX 7: Owner-based access control.
        // BEFORE: Any authenticated (or even unauthenticated) user could read any record.
        // AFTER:  Only the owner, staff, or admin may view a record.
        $currentUserId   = $decoded->user_id;
        $currentUserRole = $decoded->role;
        $recordOwnerId   = $person['user_id'];

        if ($currentUserId !== $recordOwnerId && !in_array($currentUserRole, ['staff', 'admin'])) {
            return jsonResponse($response, ['error' => 'Access denied.'], 403);
        }

        return jsonResponse($response, ['person' => $person]);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// PUT /api/persons/{id} — update a record (owner or admin).
$app->put('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo  = getPDO();
        $data = getRequestData($request);

        // ✅ FIX 6: Require valid JWT.
        $decoded = verifyTokenFromRequest($request);
        if (!$decoded) {
            return jsonResponse($response, ['error' => 'Unauthorized.'], 401);
        }

        $id = (int) $args['id'];

        // ✅ FIX 4: Prepared statement to fetch existing record.
        $stmt = $pdo->prepare('SELECT * FROM persons WHERE id = ?');
        $stmt->execute([$id]);
        $person = $stmt->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found.'], 404);
        }

        // ✅ FIX 7: Ownership check for update — only owner or admin may edit.
        $currentUserId   = $decoded->user_id;
        $currentUserRole = $decoded->role;
        $recordOwnerId   = $person['user_id'];

        if ($currentUserId !== $recordOwnerId && $currentUserRole !== 'admin') {
            return jsonResponse($response, ['error' => 'Access denied.'], 403);
        }

        // ✅ FIX 1: Validate incoming update data.
        $validationError = validateBmiInput($data);
        if ($validationError) {
            return jsonResponse($response, ['error' => $validationError], 400);
        }

        // ✅ FIX 9: Prevent mass assignment / unauthorized field update.
        // BEFORE: A loop over $allowedInInsecureStarter let the frontend update user_id, bmi, category, etc.
        // AFTER:  Only name, age, height, weight, notes are accepted from the client.
        //         user_id, bmi, category, and password_hash are always controlled by the backend.
        $name   = trim($data['name']);
        $age    = (int)   $data['age'];
        $height = (float) $data['height'];
        $weight = (float) $data['weight'];
        $notes  = trim($data['notes'] ?? '');

        // ✅ FIX 2 (part): Recalculate BMI and category after update — frontend values ignored.
        $bmi      = calculateBmi($height, $weight);
        $category = getBmiCategory($bmi);

        // ✅ FIX 4: Prepared statement for update.
        $stmt = $pdo->prepare(
            'UPDATE persons
             SET name = :name, age = :age, height = :height, weight = :weight,
                 bmi = :bmi, category = :category, notes = :notes
             WHERE id = :id'
        );
        $stmt->execute([
            ':name'     => $name,
            ':age'      => $age,
            ':height'   => $height,
            ':weight'   => $weight,
            ':bmi'      => $bmi,
            ':category' => $category,
            ':notes'    => $notes,
            ':id'       => $id,
        ]);

        // ✅ FIX 10: Return safe fields only.
        $stmt = $pdo->prepare(
            'SELECT id, user_id, name, age, height, weight, bmi, category, notes, created_at
             FROM persons WHERE id = ?'
        );
        $stmt->execute([$id]);
        $updated = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'BMI record updated.',
            'person'  => $updated
        ]);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// DELETE /api/persons/{id} — delete a record (owner or admin).
$app->delete('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();

        // ✅ FIX 6: Require valid JWT.
        $decoded = verifyTokenFromRequest($request);
        if (!$decoded) {
            return jsonResponse($response, ['error' => 'Unauthorized.'], 401);
        }

        $id = (int) $args['id'];

        // ✅ FIX 4: Prepared statement.
        $stmt = $pdo->prepare('SELECT user_id FROM persons WHERE id = ?');
        $stmt->execute([$id]);
        $person = $stmt->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found.'], 404);
        }

        // ✅ FIX 7: Ownership check for delete — only owner or admin may delete.
        // BEFORE: No auth, no ownership check, no role check — anyone could delete any record.
        // AFTER:  Only the record owner or an admin can delete.
        $currentUserId   = $decoded->user_id;
        $currentUserRole = $decoded->role;
        $recordOwnerId   = $person['user_id'];

        if ($currentUserId !== $recordOwnerId && $currentUserRole !== 'admin') {
            return jsonResponse($response, ['error' => 'Access denied.'], 403);
        }

        // ✅ FIX 4: Prepared statement for delete.
        $stmt = $pdo->prepare('DELETE FROM persons WHERE id = ?');
        $stmt->execute([$id]);

        return jsonResponse($response, ['message' => 'BMI record deleted.']);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// ----------------------------------------------------------
// Staff routes
// ----------------------------------------------------------

// GET /api/staff/persons — view all BMI records (staff or admin only).
$app->get('/api/staff/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        // ✅ FIX 6: Require valid JWT.
        $decoded = verifyTokenFromRequest($request);
        if (!$decoded) {
            return jsonResponse($response, ['error' => 'Unauthorized.'], 401);
        }

        // ✅ FIX 8: Role-Based Access Control (RBAC) — staff route.
        // BEFORE: No role check; any request (even without a token) returned all records.
        // AFTER:  Only users with role 'staff' or 'admin' are allowed.
        if (!in_array($decoded->role, ['staff', 'admin'])) {
            return jsonResponse($response, ['error' => 'Staff access required.'], 403);
        }

        // ✅ FIX 4 + FIX 10: Prepared statement + safe fields; no password_hash in JOIN.
        $stmt = $pdo->prepare(
            'SELECT persons.id, persons.user_id, persons.name, persons.age,
                    persons.height, persons.weight, persons.bmi, persons.category,
                    persons.notes, persons.created_at,
                    users.email AS owner_email, users.role AS owner_role
             FROM persons
             JOIN users ON persons.user_id = users.id
             ORDER BY persons.id DESC'
        );
        $stmt->execute();
        $persons = $stmt->fetchAll();

        return jsonResponse($response, ['persons' => $persons]);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// GET /api/staff/persons/{id} — view one record (staff or admin).
$app->get('/api/staff/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();

        // ✅ FIX 6: Require valid JWT.
        $decoded = verifyTokenFromRequest($request);
        if (!$decoded) {
            return jsonResponse($response, ['error' => 'Unauthorized.'], 401);
        }

        // ✅ FIX 8: RBAC — staff or admin only.
        if (!in_array($decoded->role, ['staff', 'admin'])) {
            return jsonResponse($response, ['error' => 'Staff access required.'], 403);
        }

        $id = (int) $args['id'];

        // ✅ FIX 4 + FIX 10: Prepared statement + safe field selection.
        $stmt = $pdo->prepare(
            'SELECT persons.id, persons.user_id, persons.name, persons.age,
                    persons.height, persons.weight, persons.bmi, persons.category,
                    persons.notes, persons.created_at,
                    users.email AS owner_email, users.role AS owner_role
             FROM persons
             JOIN users ON persons.user_id = users.id
             WHERE persons.id = ?'
        );
        $stmt->execute([$id]);
        $person = $stmt->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found.'], 404);
        }

        return jsonResponse($response, ['person' => $person]);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// ----------------------------------------------------------
// Admin routes
// ----------------------------------------------------------

// GET /api/admin/users — list all users (admin only).
$app->get('/api/admin/users', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        // ✅ FIX 6: Require valid JWT.
        $decoded = verifyTokenFromRequest($request);
        if (!$decoded) {
            return jsonResponse($response, ['error' => 'Unauthorized.'], 401);
        }

        // ✅ FIX 8: RBAC — admin only.
        // BEFORE: No role check; any request could list all users including their password hashes.
        // AFTER:  Only role === 'admin' is allowed through.
        if ($decoded->role !== 'admin') {
            return jsonResponse($response, ['error' => 'Admin access required.'], 403);
        }

        // ✅ FIX 4 + FIX 10: Prepared statement + safe columns (no password_hash).
        $stmt = $pdo->prepare('SELECT id, name, email, role, created_at FROM users ORDER BY id ASC');
        $stmt->execute();
        $users = $stmt->fetchAll();

        return jsonResponse($response, ['users' => $users]);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// PUT /api/admin/users/{id}/role — change a user's role (admin only).
$app->put('/api/admin/users/{id}/role', function (Request $request, Response $response, array $args) {
    try {
        $pdo  = getPDO();
        $data = getRequestData($request);

        // ✅ FIX 6: Require valid JWT.
        $decoded = verifyTokenFromRequest($request);
        if (!$decoded) {
            return jsonResponse($response, ['error' => 'Unauthorized.'], 401);
        }

        // ✅ FIX 8: RBAC — admin only.
        // BEFORE: Anyone could hit this endpoint and promote themselves or others to admin.
        // AFTER:  Only an admin can change roles.
        if ($decoded->role !== 'admin') {
            return jsonResponse($response, ['error' => 'Admin access required.'], 403);
        }

        $id = (int) $args['id'];

        // ✅ FIX 9 (part): Whitelist allowed role values — prevents arbitrary role strings.
        $allowedRoles = ['user', 'staff', 'admin'];
        $role         = $data['role'] ?? '';

        if (!in_array($role, $allowedRoles)) {
            return jsonResponse($response, ['error' => 'Invalid role. Allowed: user, staff, admin.'], 400);
        }

        // ✅ FIX 4: Prepared statement.
        $stmt = $pdo->prepare('UPDATE users SET role = ? WHERE id = ?');
        $stmt->execute([$role, $id]);

        // ✅ FIX 10: Safe field selection.
        $stmt = $pdo->prepare('SELECT id, name, email, role FROM users WHERE id = ?');
        $stmt->execute([$id]);
        $user = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'User role updated.',
            'user'    => $user
        ]);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// DELETE /api/admin/persons/{id} — delete any BMI record (admin only).
$app->delete('/api/admin/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();

        // ✅ FIX 6: Require valid JWT.
        $decoded = verifyTokenFromRequest($request);
        if (!$decoded) {
            return jsonResponse($response, ['error' => 'Unauthorized.'], 401);
        }

        // ✅ FIX 8: RBAC — admin only.
        // BEFORE: No admin role check; any request could delete any record.
        // AFTER:  Only admin may use this endpoint.
        if ($decoded->role !== 'admin') {
            return jsonResponse($response, ['error' => 'Admin access required.'], 403);
        }

        $id = (int) $args['id'];

        // ✅ FIX 4: Prepared statement for delete.
        $stmt = $pdo->prepare('DELETE FROM persons WHERE id = ?');
        $stmt->execute([$id]);

        return jsonResponse($response, ['message' => 'BMI record deleted by admin.']);

    } catch (\Throwable $e) {
        return handleException($response, $e);
    }
});

// Preflight catch-all
$app->options('/{routes:.+}', function (Request $request, Response $response) {
    return $response;
});

$app->run();
