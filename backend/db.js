const { DatabaseSync } = require('node:sqlite');

// 메모리 SQLite — 서버를 재시작하면 초기화됩니다. (교육용 데모 목적, 실제 개인정보 없음)
const db = new DatabaseSync(':memory:');

db.exec(`
  -- 레벨마다 완전히 별도의 테이블을 둡니다 (WHERE절에 level 조건만 덧붙이는 방식은
  -- "-- " 주석 공격에 뒤쪽 조건이 통째로 날아가버려서 레벨 분리가 무력화되는 문제가 있었습니다.
  -- 테이블 자체를 분리하면 주석으로 WHERE절을 다 지워도 그 테이블 안의 데이터만 보이므로 안전합니다).
  -- Lv.1(취약)과 Lv.4(패치)는 "같은 계정에 같은 공격을 시도했을 때 패치 전/후 차이"를 보여주는 짝이라
  -- 일부러 같은 테이블(users_lv1)을 공유합니다. Lv.3과 Challenge는 서로 다른 기법을 쓰는 별개의
  -- 레벨이라 각자 다른 테이블을 둬서, 한 레벨에서 알아낸 값으로 다른 레벨이 풀리지 않게 합니다.
  CREATE TABLE users_lv1 (
    id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, secret TEXT
  );
  CREATE TABLE users_lv3 (
    id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, secret TEXT
  );
  CREATE TABLE users_challenge (
    id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, secret TEXT
  );
  CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL
  );

  -- Challenge는 2단계 구성입니다.
  -- Stage 1(로그인 우회, Lv.3과 같은 필터 우회 기법)을 풀어도 진짜 FLAG는 안 주고 "다음 단계 힌트"만 줍니다.
  -- Stage 2(상품 검색, Lv.2/Lv.5와 같은 UNION SELECT 기법)로 challenge_vault를 직접 조회해야 진짜 FLAG가 나옵니다.
  -- 즉 Lv.3 기법과 Lv.5 기법을 순서대로 둘 다 써야 끝까지 풀립니다.
  CREATE TABLE challenge_products (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL
  );
  CREATE TABLE challenge_vault (
    id INTEGER PRIMARY KEY, flag TEXT NOT NULL
  );

  INSERT INTO users_lv1 (username, password, secret) VALUES
    ('admin', 'Str1ngB3nd!', 'Lv.1 돌파 — 문자열 연결형 SQL Injection으로 로그인 우회 성공'),
    ('guest', 'guest123', NULL);
  INSERT INTO users_lv3 (username, password, secret) VALUES
    ('admin', 'F1lt3rByp@ss', 'Lv.3 돌파 — OR 블랙리스트 필터를 OORR 트릭으로 우회');
  INSERT INTO users_challenge (username, password, secret) VALUES
    ('admin', 'Ch4lleng3W1n!', 'Stage 1 돌파. 다음 단계: 상품 검색 API(Challenge 전용)에 UNION SELECT를 써보세요. 컬럼은 2개입니다.');

  INSERT INTO products (id, name) VALUES
    (1, '무선 키보드'),
    (2, '노트북 거치대'),
    (999, '[기밀] 미출시 신제품 스펙');

  INSERT INTO challenge_products (id, name) VALUES
    (1, '한정판 머그컵'),
    (2, '스티커 세트');
  INSERT INTO challenge_vault (id, flag) VALUES
    (1, 'FLAG{SQLI_CHAIN_COMPLETE}');
`);

// level 문자열 → 실제 테이블 이름. server.js가 라우트별로 고정해서 넘기는 값만 쓰이므로
// (요청 바디에서 받은 값이 아님) 테이블명 자체에 사용자 입력이 섞일 일은 없습니다.
const USER_TABLE = { lv1: 'users_lv1', lv3: 'users_lv3', challenge: 'users_challenge' };

// 시드 데이터를 넣은 뒤에는 읽기 전용으로 잠가둡니다.
// 이 실습에서 필요한 건 SELECT뿐이라, 주입된 구문으로 데이터가 바뀌는 일을 막기 위한 안전장치입니다.
db.exec('PRAGMA query_only = ON');

// 쿼리를 실행하고 항상 { sql, rows, error } 형태로 돌려줍니다. (프론트와 약속한 응답 형식)
function run(sql, params = []) {
  try {
    const rows = db.prepare(sql).all(...params).map((r) => ({ ...r }));
    return { sql, rows, error: null };
  } catch (e) {
    return { sql, rows: [], error: e.message };
  }
}

// Lv.3 / Challenge 에서 쓰는 블랙리스트 필터: 'or' 를 (대소문자 무시) 한 번에 전부 제거
const stripOr = (s) => String(s).replace(/or/gi, '');

// ---------- 로그인 (Lv.1, Lv.3, Lv.4, Challenge) ----------
// level은 사용자 입력이 아니라 server.js가 라우트별로 고정해서 넘기는 값(USER_TABLE로 테이블명을
// 고르는 용도로만 씀)이라, 이걸로 테이블을 나눠도 사용자 입력이 테이블명에 섞여 들어갈 일은 없습니다.

// ⚠ 취약: 문자열 연결
function vulnerableLogin(username, password, level = 'lv1') {
  const table = USER_TABLE[level] || USER_TABLE.lv1;
  return run(`SELECT * FROM ${table} WHERE username='${username}' AND password='${password}'`);
}

// ⚠ 취약: 'or' 필터만 걸어둔 문자열 연결 (Lv.3, Challenge — 서로 다른 level 값으로 호출됨)
function filteredLogin(username, password, level = 'lv3') {
  return vulnerableLogin(stripOr(username), stripOr(password), level);
}

// ✅ 안전: Prepared Statement. 바인딩된 값(params)도 함께 돌려줘서 "구조와 값의 분리"를 보여줄 수 있음
// Lv.4는 일부러 Lv.1과 같은 테이블(users_lv1)을 대상으로 해서 "똑같은 공격이 패치 후엔 안 통한다"를 보여줍니다.
function patchedLogin(username, password, level = 'lv1') {
  const table = USER_TABLE[level] || USER_TABLE.lv1;
  const result = run(`SELECT * FROM ${table} WHERE username=? AND password=?`, [username, password]);
  return { ...result, params: [username, password] };
}

// ---------- 상품 조회 (Lv.2) ----------

// ⚠ 취약: 숫자형 파라미터를 따옴표 없이 그대로 삽입
function vulnerableProduct(id) {
  return run(`SELECT * FROM products WHERE id=${id}`);
}

// ✅ 안전: 파라미터 바인딩
function patchedProduct(id) {
  const result = run('SELECT * FROM products WHERE id=?', [id]);
  return { ...result, params: [id] };
}

// ---------- Challenge Stage 2: 상품 검색 (Lv.2/Lv.5와 같은 취약 패턴, challenge_vault 전용 타겟) ----------

// ⚠ 취약: 숫자형 파라미터를 따옴표 없이 그대로 삽입 (UNION SELECT로 challenge_vault를 노려야 진짜 FLAG가 나옴)
function vulnerableChallengeSearch(id) {
  return run(`SELECT * FROM challenge_products WHERE id=${id}`);
}

// ========== XSS ==========

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Lv.3 / Challenge 에서 쓰는 블랙리스트 필터: 'script' 를 (대소문자 무시) 한 번에 전부 제거
const stripScript = (s) => String(s).replace(/script/gi, '');

// ---------- Lv.1 Reflected XSS: 검색어를 즉시 그 응답에만 반영 ----------

// ⚠ 취약: 이스케이프 없이 그대로 삽입
function xssVulnerable(q) {
  return `<p>검색어: ${q} 에 대한 결과가 없습니다.</p>`;
}

// ✅ 안전: 출력 시 HTML 엔티티 인코딩
function xssPatched(q) {
  return `<p>검색어: ${escapeHtml(q)} 에 대한 결과가 없습니다.</p>`;
}

// ---------- Lv.2~4, Challenge: Stored XSS — 댓글이 서버 메모리에 쌓여 모든 열람자에게 노출 ----------
// 레벨별로 독립된 댓글함을 둬서, 한 레벨에 올린 댓글이 다른 레벨에 안 섞이게 함.
const commentStores = { lv2: [], lv3: [], lv4: [], challenge: [] };

function listComments(level) {
  return { comments: commentStores[level] || [] };
}

// Lv.4 전용: 저장은 원본 그대로지만, 조회 시에는 항상 이스케이프해서 돌려줌
// (POST 응답뿐 아니라 새로고침 후 GET 조회에서도 패치가 똑같이 적용돼야 하므로 분리)
function listCommentsEscaped(level) {
  return { comments: (commentStores[level] || []).map(escapeHtml) };
}

// ⚠ 취약 (Lv.2): 필터도, 이스케이프도 없음
function postCommentVulnerable(level, comment) {
  commentStores[level].push(String(comment));
  return listComments(level);
}

// ⚠ 취약 (Lv.3, Challenge): script 블랙리스트 필터만 적용 — <img onerror=...> 등으로 우회 가능
function postCommentFiltered(level, comment) {
  commentStores[level].push(stripScript(String(comment)));
  return listComments(level);
}

// ✅ 안전 (Lv.4): 저장은 원본 그대로 하되, 출력 시 이스케이프
function postCommentPatched(level, comment) {
  commentStores[level].push(String(comment)); // 저장은 그대로
  return listCommentsEscaped(level); // 출력만 안전하게 (GET 조회 때와 동일한 함수 사용)
}

function resetComments(level) {
  if (commentStores[level]) commentStores[level] = [];
  return listComments(level);
}

module.exports = {
  // SQLi
  vulnerableLogin,
  filteredLogin,
  patchedLogin,
  vulnerableProduct,
  patchedProduct,
  vulnerableChallengeSearch,
  // XSS
  xssVulnerable,
  xssPatched,
  listComments,
  listCommentsEscaped,
  postCommentVulnerable,
  postCommentFiltered,
  postCommentPatched,
  resetComments,
};
