# DB Migration: summary_1line

목적: 카드 목록용 1줄 요약(`summary_1line`)을 기사 저장 시점에 함께 보관.

## SQL
```sql
ALTER TABLE topic_articles
  ADD COLUMN summary_1line VARCHAR(255) NULL AFTER headline;
```

## 적용 순서
1. DB에서 위 ALTER 실행
2. cafe24 API 파일 업로드
  - `article_upsert.php`
  - `articles_list.php`
  - `article_get.php`
  - `article_latest.php`
3. Worker 배포 (`worker/src/index.ts`)
4. 수동 생성 1회 실행 후 목록 UI에서 1줄 요약 확인

## 하위 호환
- 컬럼이 아직 없어도 API는 fallback 동작하도록 구현되어 있음.
- 컬럼이 생기면 OpenAI가 생성한 `summary_1line`을 우선 사용.

