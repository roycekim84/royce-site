<?php
declare(strict_types=1);

require_once __DIR__ . '/_auth.php';

require_internal_auth();

try {
  $pdo = db();
  $row = $pdo->query('SELECT 1 AS one')->fetch();
  out([
    'ok' => true,
    'service' => 'cafe24-internal-api',
    'db' => [
      'connected' => true,
      'test' => $row,
    ],
    'ts' => date('c'),
  ]);
} catch (Throwable $e) {
  out([
    'ok' => false,
    'service' => 'cafe24-internal-api',
    'db' => [
      'connected' => false
    ],
    'error' => $e->getMessage(),
  ], 500);
}
