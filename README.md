# Web Security Lab — OWASP Top 10 실습실

보안 취약점 학습용 시뮬레이터입니다. 두 가지 모드로 동작합니다.

- **시뮬레이션 모드** — 서버 없이 정적 파일만으로, 브라우저 안 자체 로직으로 동작
- **실제 서버 모드** — `backend/`의 Express + SQLite 서버를 켜면, 진짜 쿼리/진짜 HTML 응답으로 동작

## 지금 상태 (역할별 진행 상황)

| 영역 | 상태 |
|---|---|
| 백엔드 API (SQLi Lv.1~4 + Challenge, XSS Lv.1~4 + Challenge) | ✅ 전부 구현 + curl 테스트 완료 |
| 프론트엔드 연동 (`sqli.html`) | ✅ Lv.1~4, Challenge 전부 연동 완료 |
| 프론트엔드 연동 (`xss.html`) | 아직 연동 안 됨. **C가 작업** |
| GitHub 연동 배포 | 아직 시작 안 함 |

API 전체 명세는 **[API.md](./API.md)** 참고 — 경로, 요청/응답 형식, 연동 코드 예시가 다 들어있습니다.

## 파일 구조

```
sqli-lab/
├── index.html    ← 허브 페이지
├── sqli.html     ← SQL Injection 실습 (전체 백엔드 연동됨)
├── xss.html      ← XSS 실습 (아직 시뮬레이션 모드만)
├── API.md        ← 전체 API 명세서 (B, C가 보고 연동하면 됨)
├── backend/
│   ├── server.js   ← Express 서버 (정적 파일 서빙 + 전체 API 라우트)
│   ├── db.js       ← SQLite 쿼리 로직 (레벨별 취약/패치 버전)
│   └── package.json
└── README.md
```

## 방법 A — 서버 없이 시뮬레이션만 보기

```bash
python3 -m http.server 8000
```
`http://localhost:8000` 접속. 모든 레벨이 브라우저 자체 로직으로 동작합니다.

## 방법 B — 실제 백엔드까지 켜서 보기 (추천)

**Node.js 22.5 이상**이 필요합니다 (내장 `node:sqlite` 모듈 사용, 별도 DB 설치 불필요).
```bash
node -v   # v22.5.0 이상인지 확인
```
버전이 낮다면:
```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
```

서버 실행:
```bash
cd sqli-lab/backend
npm install
node server.js
```
`http://localhost:3000` 으로 접속하세요. (python http.server 말고 이 주소로 들어가야 실제 서버가 같이 동작합니다.)

**확인 방법**: `sqli.html`의 Lv.1 화면 상단에 `🟢 실제 백엔드 서버 연결됨` 배지가 뜨면 성공입니다. 이 상태에서 로그인 우회를 시도하면, 그 결과는 브라우저 안 시뮬레이션이 아니라 **진짜 Node.js 서버가 진짜 SQLite에 쿼리를 날려서** 나온 결과입니다.

백엔드가 꺼져 있으면 Lv.1도 자동으로 "백엔드에 연결할 수 없습니다" 안내가 뜨고, 다른 레벨들은 평소처럼 시뮬레이션으로 동작합니다.

## API로 직접 확인해보기 (프론트 없이)

```bash
# 실제 SQL Injection — rows에 사용자 2명이 다 나오면 우회 성공
curl -X POST http://localhost:3000/api/sqli/lv1/vulnerable \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin' OR '1'='1' -- \",\"password\":\"x\"}"

# Lv.3 필터 우회 — OR은 막히지만 OORR은 뚫림
curl -X POST http://localhost:3000/api/sqli/lv3/vulnerable \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin' OORR '1'='1' -- \",\"password\":\"x\"}"

# XSS Lv.3 필터 우회 — script는 막히지만 img onerror는 통과
curl -X POST http://localhost:3000/api/xss/lv3/comments \
  -H 'Content-Type: application/json' \
  -d '{"comment":"<img src=x onerror=alert(1)>"}'
```
전체 엔드포인트 목록과 레벨별 동작 방식은 [API.md](./API.md)에 정리되어 있습니다.

## 다음 할 일

- [x] `sqli.html` Lv.2~4, Challenge를 API.md 보고 `fetch` 연동 — Lv.1 패턴 재사용, 레벨별 성공 판정까지 반영
- [ ] (C) `xss.html` Lv.1~4, Challenge를 API.md 보고 `fetch` 연동
- [ ] SQLite를 메모리(`:memory:`) 대신 파일로 바꿔서 재시작해도 데이터 유지 (선택)
- [ ] `backend/`를 GitHub에 올리고 Render 등에 연결해서 실제 배포

## 각 모듈 수정 포인트

### sqli.html / xss.html
- `LEVELS` 배열 — 레벨별 이론/힌트/로직/해설. `backend` 필드가 있으면 그 레벨은 실제 서버로 요청을 보냅니다 (SQLi는 Lv.1~4, Challenge 전체에 적용됨).
- `tokenize()` / `parseWhere()` / `evalBool()` (sqli.html) — 시뮬레이션 모드에서 쓰는 자체 SQL 파서
- `detectExecuted()` (xss.html) — XSS 실행 여부를 판정하는 패턴 규칙

### backend/db.js
- SQLi: `vulnerableLogin` / `filteredLogin` / `patchedLogin` (로그인류), `vulnerableProduct` / `patchedProduct` (Lv.2)
- XSS: `xssVulnerable` / `xssPatched` (Lv.1), `postCommentVulnerable` / `postCommentFiltered` / `postCommentPatched` (Lv.2~4, Challenge 댓글)
- 새 레벨이나 새 취약점을 추가하고 싶으면 이 파일에 함수를 추가하고 `server.js`에 라우트를 추가하면 됩니다.
