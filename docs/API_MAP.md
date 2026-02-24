# API Map

Last updated: 2026-02-24  
Main router: `worker/src/index.ts`

## Public (No Login)
- `GET /api/health`
- `GET /api/public/topics`
- `GET /api/public/articles?topic_id=&limit=`
- `GET /api/public/article?article_id=`

## Auth
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `POST /api/auth/register` -> currently disabled (404 by design)
- `GET /api/me`

## My Topics (Login required)
- `GET /api/my/topics`
- `POST /api/my/topics` `{ title }`
- `DELETE /api/my/topics?topic_id=`

## Articles (Login required)
- `GET /api/articles?topic_id=&limit=`
- `GET /api/article?article_id=`
- `GET /api/articles/latest?topic_id=`
- `POST /api/articles/generate-24h?topic_id=`

## Admin/Job Token Route
- `POST /api/articles/generate?topic_id=` with header `X-News-Token`

## Worker Scheduled Jobs
- `0 21 * * *` (UTC): 정기 생성
- `0 9 * * *` (UTC): 정기 생성
- `0 0 1 * *` (UTC): 월간 정리(30일 초과 뉴스 삭제)

## Internal PHP APIs (cafe24)
- 주요 조회/인증:
  - `users_verify.php`
  - `active_topics.php`
  - `user_topics_list.php`
  - `articles_list.php`
  - `article_get.php`
  - `article_latest.php`
- 주요 쓰기:
  - `topic_upsert.php`
  - `user_topics_add.php`
  - `user_topics_remove.php`
  - `article_upsert.php`
  - `purge_old_news.php` (월간 정리용)

