# Web Security Lab — OWASP Top 10 실습실

보안 취약점 학습용 시뮬레이터입니다. 두 가지 모드로 동작합니다.

- **시뮬레이션 모드** — 서버 없이 정적 파일만으로, 브라우저 안 자체 로직으로 동작
- **실제 서버 모드** — `backend/`의 Express + SQLite 서버를 켜면, 진짜 쿼리/진짜 HTML 응답으로 동작

## 지금 상태 (역할별 진행 상황)

| 영역 | 상태 |
|---|---|
| 백엔드 API — SQLi (Lv.1~5, Challenge 2단계) | ✅ 전부 구현 + curl 테스트 완료 |
| 백엔드 API — Blind SQL Injection (Lv.1, Lv.2, Challenge) | ✅ 전부 구현 + curl 테스트 완료 |
| 백엔드 API — XSS (Lv.1~4, Challenge) | ✅ 전부 구현 + curl 테스트 완료 |
| 백엔드 API — IDOR (Lv.1~5) | ✅ 전부 구현 완료 |
| 프론트엔드 연동 (`sqli.html`) | ✅ Lv.1~5, Challenge(Stage1/2), Blind 카테고리까지 전부 연동 완료 |
| 프론트엔드 연동 (`xss.html`) | ✅ Lv.1~4, Challenge 전부 연동 완료 |
| 프론트엔드 연동 (`idor.html`) | ✅ Lv.1~5(파라미터 조작/헤더 우회/다중 객체 참조/인코딩 우회/최종 챌린지) 전부 연동 완료 |
| 이론 설명 가독성 | ✅ sqli/xss/idor 세 페이지 모두 기초 이론을 접이식(아코디언)으로 정리 + 핵심 한 줄 요약 추가 |
| GitHub 업로드 | ✅ PR로 작업 중, main에는 merge된 부분만 반영됨 (Render 등 실제 호스팅 배포는 아직 안 함) |

API 전체 명세는 **[API.md](./API.md)** 참고 — 경로, 요청/응답 형식, 연동 코드 예시가 다 들어있습니다.

## 파일 구조

```
(repo 루트)
├── index.html    ← 허브 페이지
├── sqli.html     ← SQL Injection 실습 (일반 Lv.1~5/Challenge + Blind Lv.1~2/Challenge, 전체 백엔드 연동됨)
├── xss.html      ← XSS 실습 (전체 백엔드 연동됨)
├── idor.html     ← IDOR 실습 (Lv.1~5, 전체 백엔드 연동됨)
├── API.md        ← 전체 API 명세서
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
cd backend
npm install
node server.js
```
`http://localhost:3000` 으로 접속하세요. (python http.server 말고 이 주소로 들어가야 실제 서버가 같이 동작합니다.)

**확인 방법**: `sqli.html` / `xss.html` 화면 상단에 `🟢 실제 백엔드 서버 연결됨` 배지가 뜨면 성공입니다. 이 상태에서 SQLi Lv.1~5/Challenge, Blind SQLi, XSS Lv.1~4/Challenge 아무 레벨에서나 공격을 시도하면, 그 결과는 브라우저 안 시뮬레이션이 아니라 **진짜 Node.js 서버가 진짜 SQLite에 쿼리를 날려서** 나온 결과입니다. (`idor.html`은 아직 백엔드 연동이 안 되어 있어 이 배지와 무관하게 항상 로컬 mock으로만 동작합니다.)

백엔드가 꺼져 있으면 SQLi, XSS 모든 레벨이 자동으로 "백엔드에 연결할 수 없습니다" 안내로 전환되고, 그대로 브라우저 시뮬레이션으로 이어서 진행할 수 있습니다.

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

# Lv.5 UNION SELECT — vault_lv5의 비밀 값이 상품 목록 자리에 노출됨
curl -X POST http://localhost:3000/api/sqli/lv5/vulnerable \
  -H 'Content-Type: application/json' \
  -d '{"id":"0 UNION SELECT id, secret FROM vault_lv5 -- "}'

# Blind SQLi Lv.1 — 데이터 노출 없이 matched(참/거짓)만 돌아옴
curl -X POST http://localhost:3000/api/sqli/blind/lv1/vulnerable \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin' AND SUBSTR(password,1,1)='B' -- \"}"

# XSS Lv.3 필터 우회 — script는 막히지만 img onerror는 통과
curl -X POST http://localhost:3000/api/xss/lv3/comments \
  -H 'Content-Type: application/json' \
  -d '{"comment":"<img src=x onerror=alert(1)>"}'
```
전체 엔드포인트 목록과 레벨별 동작 방식은 [API.md](./API.md)에 정리되어 있습니다.

## 다음 할 일

- [x] `sqli.html` Lv.2~4, Challenge를 API.md 보고 `fetch` 연동 — Lv.1 패턴 재사용, 레벨별 성공 판정까지 반영
- [x] `xss.html` Lv.1~4, Challenge를 API.md 보고 `fetch` 연동
- [x] SQLi Lv.5(UNION SELECT) 독립 레벨 추가, Challenge를 Stage1/2 2단계 구조로 확장
- [x] Blind SQL Injection 카테고리(Lv.1, Lv.2, Challenge) 추가
- [x] `sqli.html`/`xss.html`/`idor.html` 기초 이론 설명을 접이식(아코디언) + 핵심 요약 한 줄로 정리 (가독성 개선)
- [x] `idor.html`을 Lv.1~5(파라미터 조작/헤더 우회/다중 객체 참조/인코딩 우회/최종 챌린지) 구조로 재구현 + 백엔드 연동
- [ ] SQLite를 메모리(`:memory:`) 대신 파일로 바꿔서 재시작해도 데이터 유지 (선택)
- [ ] Render 등 호스팅에 연결해서 실제 배포

## 각 모듈 수정 포인트

### sqli.html
- `LEVELS` 배열 — 일반 SQLi(Lv.1~5, Challenge)의 이론/힌트/로직/해설. `backend` 필드가 있으면 실제 서버로 요청을 보냅니다.
- `BLIND_LEVELS` 배열 — Blind SQLi(Lv.1, Lv.2, Challenge) 전용. `mode:'blind'`라 일반 레벨과는 렌더링 방식이 다름 (`renderBlindStage()` 참고, 참/거짓만 보여주고 데이터는 노출 안 함).
- `renderChallengeStage()` — 종합 Challenge의 Stage1(로그인 우회)→Stage2(UNION SELECT) 전용 2단계 UI.
- 카테고리 전환(`cat` 변수, `.cat-btn`)으로 "일반 SQL Injection" ↔ "Blind SQL Injection" 탭 그룹을 바꿈.
- `tokenize()` / `parseWhere()` / `evalBool()` — 시뮬레이션 모드(백엔드 없을 때)에서 쓰는 자체 SQL 파서.

### xss.html
- `LEVELS` 배열 — 레벨별 이론/힌트/로직/해설. `backend` 필드가 있으면 그 레벨은 실제 서버로 요청을 보냅니다 (Lv.1~4, Challenge 전체에 적용됨).
- `detectExecuted()` — XSS 실행 여부를 판정하는 패턴 규칙

### idor.html
- **5단계 체계적 학습 레벨**:
  * **Lv.1**: URL 파라미터 직접 조작 (`?id=`)
  * **Lv.2**: 커스텀 헤더 권한 우회 (`X-User-Role: admin`)
  * **Lv.3**: 다중 객체 식별자 참조 우회 (계좌번호 `account_no`)
  * **Lv.4**: Base64 난독화 및 인코딩 우회 (`encoded_id`)
  * **Lv.5 (Challenge)**: 최종 플래그 검증 및 수료 인증
- **사용자 경험(UX) 최적화**:
  * 단계별 상세 아코디언 가이드 맵 제공
  * 실시간 학습 진행도 추적기 (0% ~ 100%)
  * 요청 결과 성공(`ok`, 초록색) / 실패(`fail`, 빨간색) 시각적 피드백 UI 분기
  * 단계별 누적 시도 횟수에 따른 순차적 힌트 제공 시스템
- ⚠️ **알려진 이슈**: Lv.5 최종 검증(`/api/idor/level5/verify`)이 `submitted_flag.includes('FLAG{')` 조건이라, 형식만 맞으면(`FLAG{아무거나}`) 다 통과됩니다. 엄밀하게 하려면 Lv.1~4에서 발급한 4개 FLAG와 정확히 일치하는지 검사하도록 고치는 게 좋습니다.

### backend/db.js
- SQLi 일반: `vulnerableLogin` / `filteredLogin` / `patchedLogin` (로그인류), `vulnerableProduct` / `patchedProduct` (Lv.2), `vulnerableUnionSearch` (Lv.5), `vulnerableChallengeSearch` (Challenge Stage2)
- Blind SQLi: `blindLogin` / `filteredBlindLogin` / `blindVerify`
- XSS: `xssVulnerable` / `xssPatched` (Lv.1), `postCommentVulnerable` / `postCommentFiltered` / `postCommentPatched` (Lv.2~4, Challenge 댓글)
- 레벨마다 완전히 분리된 테이블을 씁니다(`users_lv1`, `users_lv3`, `blind_lv1` 등) — 한 레벨에서 알아낸 답으로 다른 레벨이 풀리지 않게 하기 위함. 새 레벨을 추가할 땐 이 원칙을 유지해주세요.
- IDOR은 아직 `db.js`가 아니라 `server.js`에 `IDOR_USERS_DB`/`IDOR_ACCOUNTS_DB` 객체로 하드코딩되어 있습니다 (다른 모듈처럼 메모리 SQLite 테이블을 쓰지는 않음).
- 새 레벨이나 새 취약점을 추가하고 싶으면 이 파일에 함수를 추가하고 `server.js`에 라우트를 추가하면 됩니다.
