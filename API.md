# API 명세서 — Web Security Lab 백엔드

서버: `backend/server.js` (Express) · 기본 주소: `http://localhost:3000`

모든 요청/응답은 JSON입니다. 서버를 켜는 법은 `README.md` 참고.

```bash
cd backend
npm install
node server.js
```

---

## 공통

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/api/health` | 서버 동작 확인. `{ ok: true }` |

---

## SQL Injection

### Lv.1 — 로그인 우회

| 메서드 | 경로 | 요청 body | 응답 |
|---|---|---|---|
| POST | `/api/sqli/lv1/vulnerable` | `{ "username": "", "password": "" }` | `{ sql, rows, error }` |
| POST | `/api/sqli/lv1/patched` | 〃 | `{ sql, rows, error, params }` |

- `vulnerable`은 문자열 연결 방식이라 `admin' OR '1'='1' -- ` 같은 입력으로 실제 우회가 됩니다.
- `patched`는 Prepared Statement라 같은 입력을 넣어도 `rows`가 빈 배열로 나옵니다. `params`는 "값이 바인딩됐다"는 걸 화면에 보여주기 위한 필드입니다.
- `rows.length > 0`이고, 로그인한 계정이 입력한 username/password와 다르면 우회 성공으로 판정하면 됩니다. (지금 시뮬레이션 모드 로직과 동일)

### Lv.2 — 숫자형 검색

| 메서드 | 경로 | 요청 body | 응답 |
|---|---|---|---|
| POST | `/api/sqli/lv2/vulnerable` | `{ "id": "0 OR 1=1" }` | `{ sql, rows, error }` |
| POST | `/api/sqli/lv2/patched` | 〃 | `{ sql, rows, error, params }` |

- `id`는 **문자열로 그대로** 보내세요. 숫자로 변환하지 마세요 (`0 OR 1=1` 같은 페이로드가 와야 하니까요).
- 성공 판정: `rows.length > 1`이면 숨겨진 상품까지 노출된 것 (정상 조회는 1건).

### Lv.3 — 필터 우회

| 메서드 | 경로 | 요청 body | 응답 |
|---|---|---|---|
| POST | `/api/sqli/lv3/vulnerable` | `{ "username": "", "password": "" }` | `{ sql, rows, error }` |

- 서버가 `username`/`password`에서 `or`(대소문자 무시)를 전부 제거한 뒤 Lv.1과 같은 방식으로 실행합니다.
- 일반 `OR`은 필터링되어 실패하고, `OORR`처럼 겹쳐 쓰면 가운데만 지워지고 양 끝이 다시 `OR`이 되어 우회됩니다.
- patched 버전은 따로 없습니다 (Lv.4가 그 역할).

### Lv.4 — 패치된 버전

| 메서드 | 경로 | 요청 body | 응답 |
|---|---|---|---|
| POST | `/api/sqli/lv4` | `{ "username": "", "password": "" }` | `{ sql, rows, error, params }` |

- Lv.1 `patched`와 로직은 동일하고, 레벨 구분을 위해 경로만 따로 뒀습니다.

### Lv.5 — UNION SELECT

| 메서드 | 경로 | 요청 body | 응답 |
|---|---|---|---|
| POST | `/api/sqli/lv5/vulnerable` | `{ "id": "" }` | `{ sql, rows, error }` |

- Lv.2와 같은 숫자형 삽입 패턴이지만 대상 테이블(`products_lv5`)이 다릅니다. Lv.2에서 쓴 공격을 그대로 복사해도 안 풀립니다.
- `id`에 `0 UNION SELECT id, secret FROM vault_lv5 -- ` 식으로 넣으면, 평범하게는 절대 안 보이는 `vault_lv5` 테이블의 값이 상품 이름 자리에 그대로 노출됩니다.

### Challenge — 종합, 2단계 구성 (힌트 없음)

Stage 1만 풀어서는 진짜 FLAG가 안 나옵니다. Stage 1에서 받는 `secret`은 다음 단계로 가는 힌트일 뿐이고,
Stage 2(UNION SELECT)까지 풀어야 진짜 FLAG가 나옵니다.

**Stage 1 — 로그인 우회** (Lv.3과 같은 `or` 필터 기법)

| 메서드 | 경로 | 요청 body | 응답 |
|---|---|---|---|
| POST | `/api/sqli/challenge/vulnerable` | `{ "username": "", "password": "" }` | `{ sql, rows, error }` |

- 성공하면 `rows[0].secret`에 "다음 단계 힌트"가 담겨 돌아옵니다 (FLAG 아님).

**Stage 2 — 상품 검색** (Lv.2/Lv.5와 같은 숫자형 삽입 취약점)

| 메서드 | 경로 | 요청 body | 응답 |
|---|---|---|---|
| POST | `/api/sqli/challenge/search` | `{ "id": "" }` | `{ sql, rows, error }` |

- 평범하게 쓰면 `challenge_products` 테이블의 상품만 나옵니다.
- `id`에 `0 UNION SELECT id, flag FROM challenge_vault -- ` 식으로 UNION SELECT를 넣으면, `challenge_vault` 테이블의 진짜 FLAG(`FLAG{SQLI_CHAIN_COMPLETE}`)가 `name` 컬럼 자리에 노출됩니다.

---

## Blind SQL Injection

세 레벨 모두 **응답에 데이터를 절대 포함하지 않습니다.** "조건을 만족하는 행이 있었는지(참/거짓)"만 `matched` 필드로 돌려줍니다. 레벨마다 완전히 다른 테이블 + 다른 비밀번호를 써서, 한 레벨에서 알아낸 값으로 다른 레벨이 풀리지 않습니다.

### Lv.1 — Boolean-based, 필터 없음

| 메서드 | 경로 | 요청 body | 응답 |
|---|---|---|---|
| POST | `/api/sqli/blind/lv1/vulnerable` | `{ "username": "" }` | `{ sql, matched, error }` |

- 예: `admin' AND SUBSTR(password,1,1)='B' -- ` → `matched: true` (비밀번호 첫 글자가 B일 때)

### Lv.2 — 필터 우회

| 메서드 | 경로 | 요청 body | 응답 |
|---|---|---|---|
| POST | `/api/sqli/blind/lv2/vulnerable` | `{ "username": "" }` | `{ sql, matched, error }` |

- 서버가 `substr`(대소문자 무시)을 전부 제거합니다. `SUBSTR` 함수를 쓰려 하면 걸러지므로, `LIKE 'L%'` 같은 패턴 비교로 우회해야 합니다.

### Challenge — 종합 (힌트 없음)

| 메서드 | 경로 | 요청 body | 응답 |
|---|---|---|---|
| POST | `/api/sqli/blind/challenge/vulnerable` | `{ "username": "" }` | `{ sql, matched, error }` |

- Lv.2와 같은 `substr` 필터. FLAG 전체(`FLAG{BLIND_SQLI_MASTER}`)를 한 글자씩 직접 추출해야 합니다.

### 정답 확인 (세 레벨 공통)

| 메서드 | 경로 | 요청 body | 응답 |
|---|---|---|---|
| POST | `/api/sqli/blind/:level/verify` | `{ "guess": "" }` | `{ correct }` |

- `:level`은 `lv1` / `lv2` / `challenge` 중 하나.
- Prepared Statement로 비교만 하고 실제 값은 절대 응답에 포함하지 않습니다. 추출한 값이 맞는지 "정답 제출" UI에서 확인할 때 씁니다.

---

## XSS

### Lv.1 — Reflected XSS

| 메서드 | 경로 | 쿼리 파라미터 | 응답 |
|---|---|---|---|
| GET | `/api/xss/lv1/vulnerable?q=` | `q` (검색어) | `{ html }` |
| GET | `/api/xss/lv1/patched?q=` | 〃 | `{ html }` |

- `html`은 서버가 만든 HTML 조각 문자열입니다. 미리보기 iframe의 `srcdoc`에 그대로 넣으면 됩니다 (지금 시뮬레이션 모드와 동일한 패턴).
- `vulnerable`은 입력값을 이스케이프 없이 그대로 삽입, `patched`는 HTML 엔티티로 인코딩합니다.

### Lv.2~4, Challenge — Stored XSS (댓글)

레벨마다 서버 메모리에 독립된 댓글함이 있습니다 (`lv2`, `lv3`, `lv4`, `challenge`). 서버를 재시작하면 초기화됩니다.

| 메서드 | 경로 | 요청 body | 응답 |
|---|---|---|---|
| GET | `/api/xss/{level}/comments` | — | `{ comments: [...] }` |
| POST | `/api/xss/{level}/comments` | `{ "comment": "" }` | `{ comments: [...] }` (등록 후 전체 목록) |
| POST | `/api/xss/{level}/reset` | — | `{ comments: [] }` (댓글함 비우기) |

`{level}` 자리에 `lv2`, `lv3`, `lv4`, `challenge` 중 하나가 들어갑니다. 그 외 값은 `404`를 반환합니다.

레벨별 차이:
- **lv2** — 필터 없음. `<script>` 그대로 저장/반환됩니다.
- **lv3** — `script` 단어(대소문자 무시)를 서버가 제거한 뒤 저장. `<img src=x onerror=alert(1)>` 같은 비-script 벡터로 우회 가능합니다.
- **lv4** — 저장은 원본 그대로 하되, **GET으로 조회할 때마다 항상 이스케이프해서** 반환합니다 (POST 응답도 동일). 새로고침 후에도 안전해야 "패치됨"이 제대로 증명되므로, 프론트에서 **POST 응답과 GET 응답을 똑같이 신뢰**하면 됩니다.
- **challenge** — lv3과 같은 `script` 필터. 힌트 없이 스스로 우회 벡터를 찾는 게 목표.

댓글 목록은 `<div class="comment">...</div>`처럼 감싸지 않고 문자열 배열 그대로 옵니다. 프론트에서 `comments.map(c => '<div class="comment">'+c+'</div>').join('')` 식으로 감싸서 렌더링하면 지금 시뮬레이션 모드와 동일한 모양이 됩니다.

---

## 프론트 연동 패턴 (참고)

지금 `sqli.html`의 Lv.1에 이미 적용된 패턴입니다. 다른 레벨도 이 형태를 그대로 복사해서 경로만 바꾸면 됩니다.

```js
const res = await fetch('/api/sqli/lv2/vulnerable', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ id: vals.id })
});
const data = await res.json();
// data.sql, data.rows, data.error 사용
```

백엔드가 꺼져 있을 때는 `fetch`가 실패(reject)하니, `try/catch`로 감싸고 실패하면 지금처럼 "백엔드에 연결할 수 없습니다" 안내를 띄우거나 시뮬레이션 모드로 자연스럽게 넘어가게 하면 됩니다.

---

## 궁금한 점이나 바꾸고 싶은 형식이 있으면

이 명세는 초안입니다. 응답 필드 이름이나 구조가 프론트에서 쓰기 불편하면 언제든 얘기해 주세요 — 서버 쪽을 맞추는 게 더 쌉니다.
