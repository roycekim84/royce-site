# Maintenance Runbook

Last updated: 2026-02-24

## 1) Local Run

### Worker
```bash
cd /Users/roycekim/royce_lab/royce-site/worker
npm install
npm run dev -- --local --port 8787
```

### Web
```bash
cd /Users/roycekim/royce_lab/royce-site/web
python3 -m http.server 8080
```

브라우저: `http://localhost:8080`  
로컬 API를 보려면 `web/index.html`의 `API_BASE`를 `http://localhost:8787`로 임시 변경.

## 2) Deploy

### Worker deploy
```bash
export CLOUDFLARE_API_TOKEN=YOUR_TOKEN
cd /Users/roycekim/royce_lab/royce-site/worker
npm run deploy
```

### Web deploy
- Git 연동 배포라면 `commit + push` 시 자동 반영.

### cafe24 PHP deploy
- `cafe24/internal-api/*.php`는 수동 업로드(현재 Git 배포 대상 아님).

## 3) Known Hotspots (When Something Breaks)

### A. 로그인 안 됨
- 점검 순서:
1. `users_verify.php` 직접 호출 성공 여부
2. Worker `/api/auth/login` 응답 코드 + `Set-Cookie` 확인
3. 브라우저 3rd-party cookie 제한 여부 확인

### B. 요약이 fallback으로만 생성됨
- 점검 순서:
1. Worker 로그에서 `openai summary fallback` 확인
2. `OPENAI_API_KEY`, `OPENAI_MODEL` 설정 확인
3. OpenAI 응답 파싱 오류 여부 확인 (JSON schema strict 사용 중)

### C. 기사 과다 적재
- 월 1회 CRON으로 `purge_old_news.php` 호출됨.
- 수동 점검:
```bash
curl -s -X POST -H "X-Internal-Token: <TOKEN>" \
  -H "Content-Type: application/json" \
  "https://roycelab.mycafe24.com/internal-api/purge_old_news.php" \
  --data '{"days":30}'
```

## 4) Recommended Next Refactors
1. `worker/src/index.ts` 단일 파일 분리 (routes/services/utils)
2. `worker/test/index.spec.ts` 템플릿 테스트 제거 후 실제 API 테스트 작성
3. 운영용 임시 API 파일 생성/삭제 절차 문서화

