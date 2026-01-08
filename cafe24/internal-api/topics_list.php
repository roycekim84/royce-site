<?php
declare(strict_types=1);

require_once __DIR__ . '/_auth.php';
require_internal_auth();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
  out(['ok' => false, 'error' => 'Method Not Allowed'], 405);
}

try {
  $pdo = db();
  $rows = $pdo->query('SELECT id, slug, title_ko, title_en FROM topics ORDER BY id ASC')->fetchAll();
  out(['ok' => true, 'topics' => $rows]);
} catch (Throwable $e) {
  out(['ok' => false, 'error' => $e->getMessage()], 500);
}
