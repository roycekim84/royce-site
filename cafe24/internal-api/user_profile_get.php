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
if ($user_id <= 0) out(['ok' => false, 'error' => 'Invalid user_id'], 400);

try {
  $pdo = db();

  $stmt = $pdo->prepare('
    SELECT up.user_id, up.selected_topic_id, t.slug, t.title_ko, t.title_en
    FROM user_profile up
    LEFT JOIN topics t ON t.id = up.selected_topic_id
    WHERE up.user_id = :uid
    LIMIT 1
  ');
  $stmt->execute([':uid' => $user_id]);
  $row = $stmt->fetch();

  if (!$row) {
    out(['ok' => true, 'profile' => ['user_id' => $user_id, 'selected_topic_id' => null, 'topic' => null]]);
  }

  $topic = null;
  if (!empty($row['selected_topic_id'])) {
    $topic = [
      'id' => (int)$row['selected_topic_id'],
      'slug' => (string)$row['slug'],
      'title_ko' => (string)$row['title_ko'],
      'title_en' => (string)$row['title_en'],
    ];
  }

  out([
    'ok' => true,
    'profile' => [
      'user_id' => (int)$row['user_id'],
      'selected_topic_id' => $row['selected_topic_id'] !== null ? (int)$row['selected_topic_id'] : null,
      'topic' => $topic
    ]
  ]);
} catch (Throwable $e) {
  out(['ok' => false, 'error' => $e->getMessage()], 500);
}
