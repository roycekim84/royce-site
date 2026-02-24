# Royce Site

뉴스를 주제별로 수집하고, 요약 기사를 생성/저장/조회하는 프로젝트입니다.

## Structure
- `/Users/roycekim/royce_lab/royce-site/web`: 정적 프론트엔드
- `/Users/roycekim/royce_lab/royce-site/worker`: Cloudflare Worker API/스케줄러
- `/Users/roycekim/royce_lab/royce-site/cafe24/internal-api`: cafe24 PHP 내부 API
- `/Users/roycekim/royce_lab/royce-site/docs`: 운영/분석 문서

## Update (2026-02-24)
- 요약 품질 업그레이드
  - 본문 스니펫 기반 요약 강화
  - 출처 신뢰도 반영
  - 중복/재탕 억제 로직 추가
  - 멀티 레벨 요약(`summary_1line` + 상세 `body_md`) 적용
- 요약 안정성 개선
  - OpenAI 타임아웃/재시도/파싱 보강
- UI 개선
  - 로그인 카드 접기/펼치기 토글
  - 기사 목록 1줄 요약 표시
- 운영 자동화
  - 월간 정리 CRON 추가 (`0 0 1 * *`, UTC)
  - 30일 초과 기사/소스 삭제 API 연동
- 문서화
  - `PROJECT_OVERVIEW.md`, `API_MAP.md`, `MAINTENANCE_RUNBOOK.md`, `DB_MIGRATION_SUMMARY_1LINE.md`
  - 상세 변경 이력: `/Users/roycekim/royce_lab/royce-site/docs/UPDATE_LOG_2026-02-24.md`

