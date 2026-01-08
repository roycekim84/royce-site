<?php
declare(strict_types=1);

require_once __DIR__ . '/_auth.php';
require_internal_auth();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  out(['ok' => false, 'error' => 'Method Not Allowed'], 405);
}

$raw = file_get_contents('php://input') ?: '';
$body = json_decode($raw, true);

$user_id = isset($body['user_id']) ? (int)$body['user_id'] : 0;
$topic_id = array_key_exists('topic_id', $body) ? (int)$body['topic_id'] : -1;

if ($user_id <= 0) out(['ok' => false, 'error' => 'Invalid user_id'], 400);
// topic_id는 null 처리 허용(선택 해제)
if ($topic_id !== -1 && $topic_id !== 0 && $topic_id < 0) out(['ok' => false, 'error' => 'Invalid topic_id'], 400);

try {
  $pdo = db();

  if ($topic_id > 0) {
    $chk = $pdo->prepare('SELECT id FROM topics WHERE id = :tid LIMIT 1');
    $chk->execute([':tid' => $topic_id]);
    if (!$chk->fetch()) out(['ok' => false, 'error' => 'Topic not found'], 404);
  }

  // upsert
  $stmt = $pdo->prepare('
    INSERT INTO user_profile (user_id, selected_topic_id)
    VALUES (:uid, :tid)
    ON DUPLICATE KEY UPDATE selected_topic_id = VALUES(selected_topic_id)
  ');
  $stmt->execute([':uid' => $user_id, ':tid' => ($topic_id > 0 ? $topic_id : null)]);

  out(['ok' => true]);
} catch (Throwable $e) {
  out(['ok' => false, 'error' => $e->getMessage()], 500);
}
