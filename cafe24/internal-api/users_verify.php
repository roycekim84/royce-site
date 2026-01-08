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
if ($password === '') {
  out(['ok' => false, 'error' => 'Missing password'], 400);
}

try {
  $pdo = db();
  $stmt = $pdo->prepare('SELECT id, email, password_hash FROM users WHERE email = :email LIMIT 1');
  $stmt->execute([':email' => $email]);
  $user = $stmt->fetch();

  if (!$user) {
    out(['ok' => false, 'error' => 'Invalid credentials'], 401);
  }

  if (!password_verify($password, (string)$user['password_hash'])) {
    out(['ok' => false, 'error' => 'Invalid credentials'], 401);
  }

  out([
    'ok' => true,
    'user' => [
      'id' => (int)$user['id'],
      'email' => (string)$user['email'],
    ],
  ]);
} catch (Throwable $e) {
  out(['ok' => false, 'error' => $e->getMessage()], 500);
}
