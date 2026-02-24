# Royce Site Project Overview

Last updated: 2026-02-24

## 1) Goal
- 주제(Topic) 기반으로 뉴스를 수집하고
- OpenAI로 구간 요약 기사 1개를 생성/저장하고
- 웹 화면에서 조회/관리한다.

## 2) System Components
- `web/`: 정적 프론트엔드(로그인, 주제/기사 조회, 주제 추가/삭제)
- `worker/`: Cloudflare Worker API + 스케줄러(CRON) + OpenAI 호출
- `cafe24/internal-api/`: PHP 내부 API + MySQL 접근 레이어

## 3) Request/Data Flow
1. 브라우저(`web/index.html`)가 Worker API 호출 (`/api/...`)
2. Worker가 cafe24 내부 API로 프록시 호출 (`X-Internal-Token`)
3. 내부 API가 MySQL의 `users`, `topics`, `user_topics`, `topic_articles`, `article_sources` 등을 조회/갱신
4. 기사 생성 시 Worker가 Google News RSS + OpenAI Responses API를 사용

## 4) Current Major Behavior
- 게스트: 공개 토픽/기사 조회 가능 (`/api/public/*`)
- 로그인 사용자: 내 토픽 관리 + 기사 조회 가능 (`/api/my/*`, `/api/articles*`)
- 정기 생성 CRON: 하루 2회
- 정리 CRON: 매월 1회, 30일 초과 기사/소스 삭제

## 5) Key Config
- Worker env (런타임): `worker/.dev.vars` (로컬), Cloudflare Worker Variables/Secrets (운영)
- Worker 배포 설정: `worker/wrangler.jsonc`
- 내부 API 주소: `CAFE24_API_BASE` (`https://roycelab.mycafe24.com/internal-api`)

## 6) Security Notes
- 실제 비밀값(API 키/토큰/DB 비번)은 문서/코드에 하드코딩하지 않는다.
- `worker/.dev.vars`, `cafe24/`는 `.gitignore`로 제외되어야 한다.
- 임시 운영용 조회 API(예: users_list)는 사용 후 삭제한다.

