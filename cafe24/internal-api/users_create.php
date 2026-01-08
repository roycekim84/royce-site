<?php
declare(strict_types=1);

require_once __DIR__ . '/_auth.php';
require_internal_auth();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  out(['ok' => false, 'error' => 'Method Not Allowed'], 405);
}

$raw = file_get_contents('php://input') ?: '';
$body = json_decode($raw, true);

$email = isset($body['email']) ? trim((string)$body['email']) : '';
$password = isset($body['password']) ? (string)$body['password'] : '';

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  out(['ok' => false, 'error' => 'Invalid email'], 400);
}
if (strlen($password) < 8) {
  out(['ok' => false, 'error' => 'Password must be at least 8 characters'], 400);
}

try {
  $hash = password_hash($password, PASSWORD_BCRYPT);

  $pdo = db();
  $stmt = $pdo->prepare('INSERT INTO users (email, password_hash) VALUES (:email, :hash)');
  $stmt->execute([':email' => $email, ':hash' => $hash]);

  $id = (int)$pdo->lastInsertId();

  out([
    'ok' => true,
    'user' => ['id' => $id, 'email' => $email],
  ], 201);
} catch (PDOException $e) {
  // Duplicate email (MySQL 1062)
  if ((int)($e->errorInfo[1] ?? 0) === 1062) {
    out(['ok' => false, 'error' => 'Email already exists'], 409);
  }
  out(['ok' => false, 'error' => 'DB error', 'details' => $e->getMessage()], 500);
} catch (Throwable $e) {
  out(['ok' => false, 'error' => $e->getMessage()], 500);
}
