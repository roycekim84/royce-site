# Update Log (2026-02-24)

## Scope
- 뉴스 요약 품질 개선
- 로그인 UI 개선
- 데이터 정리(삭제) 자동화
- 운영/유지보수 문서화

## 1) 요약 품질/안정성 개선

### Worker (`worker/src/index.ts`)
- OpenAI 출력 스키마를 `headline + summary_1line + body_md`로 확장
- JSON schema strict + 복원 파싱 강화
- 요약 실패율 저감:
  - OpenAI 타임아웃(25초) 추가
  - 생성 재시도(최대 2회) 추가
  - `summary_1line` 누락 시 본문 기반 자동 보정
- 중복/재탕 억제:
  - 직전 기사와 유사도 비교
  - 변화가 적으면 “큰 변화 없음” 템플릿 적용
- 출처 신뢰도 반영:
  - 도메인/소스명 기반 high/medium/low 스코어링
  - 신뢰도 우선 정렬 및 저신뢰 필터
- 본문 기반 요약:
  - RSS description 활용
  - 일부 원문 `<p>` 스니펫 수집/활용

### 내부 API (`cafe24/internal-api/*`)
- `article_upsert.php`
  - `summary_1line` 저장 지원
  - 컬럼 존재 여부 확인 후 하위호환 처리
- `articles_list.php`, `article_get.php`, `article_latest.php`
  - `summary_1line` 반환 지원
  - 컬럼 미존재 시 fallback 요약 반환

### DB
- `topic_articles.summary_1line` 컬럼 도입
- 마이그레이션 가이드: `docs/DB_MIGRATION_SUMMARY_1LINE.md`

## 2) UI 개선

### Web (`web/index.html`)
- 로그인 카드를 기본 접힘으로 변경
- `로그인 열기/닫기` 토글 추가
- 목록 카드에 1줄 요약(`summary_1line`) 표시
- 모바일/데스크탑 가독성 맞춤 스타일 추가

## 3) 데이터 정리 자동화

### 내부 API
- `purge_old_news.php` 추가
  - 30일 초과 기사/소스 삭제
  - 트랜잭션 처리

### Worker 스케줄
- `wrangler.jsonc` CRON 추가: `0 0 1 * *` (매월 1회 UTC)
- Worker scheduled에서 월간 정리 분기 추가

## 4) 운영 점검 결과
- 운영 Worker 최신 배포 완료
- 생성 API/공개 조회 API 동작 확인
- `summary_1line` 1문장 저장/노출 확인
- 월간 정리 API 수동 호출 및 삭제 동작 확인

## 5) 문서 추가
- `docs/PROJECT_OVERVIEW.md`
- `docs/API_MAP.md`
- `docs/MAINTENANCE_RUNBOOK.md`
- `docs/DB_MIGRATION_SUMMARY_1LINE.md`
- `docs/UPDATE_LOG_2026-02-24.md` (this file)

