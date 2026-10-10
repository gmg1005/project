const { DatabaseSync } = require('node:sqlite');

// 메모리 SQLite — 서버를 재시작하면 초기화됩니다. (교육용 데모 목적, 실제 개인정보 없음)
const db = new DatabaseSync(':memory:');

db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL
  );
  CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL
  );
  INSERT INTO users (username, password) VALUES
    ('admin', 'S3cur3P@ss!'),
    ('guest', 'guest123');
  INSERT INTO products (id, name) VALUES
    (1, '무선 키보드'),
    (2, '노트북 거치대'),
    (999, '[기밀] 미출시 신제품 스펙');
`);

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

// ⚠ 취약: 문자열 연결
function vulnerableLogin(username, password) {
  return run(`SELECT * FROM users WHERE username='${username}' AND password='${password}'`);
}

// ⚠ 취약: 'or' 필터만 걸어둔 문자열 연결 (Lv.3, Challenge)
function filteredLogin(username, password) {
  return vulnerableLogin(stripOr(username), stripOr(password));
}

// ✅ 안전: Prepared Statement. 바인딩된 값(params)도 함께 돌려줘서 "구조와 값의 분리"를 보여줄 수 있음
function patchedLogin(username, password) {
  const result = run('SELECT * FROM users WHERE username=? AND password=?', [username, password]);
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
