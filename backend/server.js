const express = require('express');
const path = require('path');
const {
  vulnerableLogin,
  filteredLogin,
  patchedLogin,
  vulnerableProduct,
  patchedProduct,
  vulnerableChallengeSearch,
  vulnerableUnionSearch,
  blindLogin,
  filteredBlindLogin,
  blindVerify,
  xssVulnerable,
  xssPatched,
  listComments,
  listCommentsEscaped,
  postCommentVulnerable,
  postCommentFiltered,
  postCommentPatched,
  resetComments,
} = require('./db');

const app = express();
app.use(express.json());

// 요청 로그 — 브라우저에서 레벨을 실행할 때마다 터미널에 실시간으로 찍혀서,
// 프론트가 실제로 이 백엔드에 요청을 보내고 있다는 걸 눈으로 바로 확인할 수 있습니다.
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    const time = new Date().toLocaleTimeString('ko-KR', { hour12: false });
    console.log(`[${time}] ${req.method} ${req.path} ${JSON.stringify(req.body && Object.keys(req.body).length ? req.body : req.query)}`);
  }
  next();
});

// 프론트엔드(index.html, sqli.html, xss.html)를 같은 서버에서 그대로 서빙
app.use(express.static(path.join(__dirname, '..')));

app.get('/api/health', (req, res) => res.json({ ok: true }));

// ========== SQL Injection ==========

// Lv.1 로그인 우회 — 문자열 연결(취약) vs Prepared Statement(패치)
app.post('/api/sqli/lv1/vulnerable', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  res.json(vulnerableLogin(username, password, 'lv1'));
});
app.post('/api/sqli/lv1/patched', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  res.json(patchedLogin(username, password, 'lv1'));
});

// Lv.2 숫자형 검색 — 따옴표 없는 숫자 파라미터
app.post('/api/sqli/lv2/vulnerable', (req, res) => {
  const { id = '' } = req.body || {};
  res.json(vulnerableProduct(id));
});
app.post('/api/sqli/lv2/patched', (req, res) => {
  const { id = '' } = req.body || {};
  res.json(patchedProduct(id));
});

// Lv.3 필터 우회 — 서버가 'or' 블랙리스트 필터를 적용한 뒤 실행
// Lv.1과 다른 계정(level='lv3')을 대상으로 해서, Lv.1에서 알아낸 비밀번호로는 못 풉니다.
app.post('/api/sqli/lv3/vulnerable', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  res.json(filteredLogin(username, password, 'lv3'));
});

// Lv.4 패치된 버전 — Prepared Statement (Lv.1 patched와 동일 로직, 레벨 구분용 별도 경로)
// 일부러 Lv.1과 같은 계정(level='lv1')을 대상으로 해서 "Lv.1을 뚫었던 공격이 패치 후엔 안 통한다"를 보여줍니다.
app.post('/api/sqli/lv4', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  res.json(patchedLogin(username, password, 'lv1'));
});

// Challenge — 2단계 구성. 로그인(Lv.3 기법)만으로는 진짜 FLAG가 안 나오고, 아래 search(Lv.2/Lv.5 기법)까지
// 둘 다 풀어야 끝납니다. Lv.3과도 다른 계정(level='challenge')을 대상으로 해서 Lv.3 비밀번호로는 못 풉니다.

// Stage 1 — 로그인 우회. 성공해도 FLAG 대신 "다음 단계 힌트"(secret 필드)만 돌려줍니다.
app.post('/api/sqli/challenge/vulnerable', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  res.json(filteredLogin(username, password, 'challenge'));
});

// Stage 2 — 상품 검색. Lv.2/Lv.5와 같은 숫자형 삽입 취약점이라, UNION SELECT로
// challenge_vault 테이블을 직접 조회해야 진짜 FLAG가 나옵니다.
app.post('/api/sqli/challenge/search', (req, res) => {
  const { id = '' } = req.body || {};
  res.json(vulnerableChallengeSearch(id));
});

// Lv.5 — UNION SELECT (독립 정식 레벨). Lv.2와 같은 숫자형 삽입이지만 대상 테이블(products_lv5)이
// 달라서, vault_lv5를 노리려면 UNION SELECT로 컬럼 2개(id, secret)를 직접 맞춰야 합니다.
app.post('/api/sqli/lv5/vulnerable', (req, res) => {
  const { id = '' } = req.body || {};
  res.json(vulnerableUnionSearch(id));
});

// ========== Blind SQL Injection ==========
// 세 레벨 모두 서로 다른 테이블 + 다른 비밀번호를 쓰고, 응답에는 "조건을 만족하는 행이 있었는지"만
// 담겨 있습니다 (matched: true/false) — 실제 데이터는 절대 내려주지 않습니다.

// Lv.1 — Boolean-based, 필터 없음
app.post('/api/sqli/blind/lv1/vulnerable', (req, res) => {
  const { username = '' } = req.body || {};
  res.json(blindLogin(username, 'lv1'));
});

// Lv.2 — Boolean-based, substr 함수 이름 블랙리스트 필터 (LIKE로 우회해야 함)
app.post('/api/sqli/blind/lv2/vulnerable', (req, res) => {
  const { username = '' } = req.body || {};
  res.json(filteredBlindLogin(username, 'lv2'));
});

// Challenge — Lv.2와 같은 substr 필터, 힌트 없이 FLAG 전체를 한 글자씩 추출하는 게 목표
app.post('/api/sqli/blind/challenge/vulnerable', (req, res) => {
  const { username = '' } = req.body || {};
  res.json(filteredBlindLogin(username, 'challenge'));
});

// 정답 확인 — 추출한 값이 맞는지만 알려주고, 틀려도 실제 값은 절대 노출하지 않음
const BLIND_LEVELS = ['lv1', 'lv2', 'challenge'];
app.post('/api/sqli/blind/:level/verify', (req, res) => {
  if (!BLIND_LEVELS.includes(req.params.level)) {
    return res.status(404).json({ error: 'unknown level' });
  }
  const { guess = '' } = req.body || {};
  res.json(blindVerify(guess, req.params.level));
});

// ========== XSS ==========

// Lv.1 Reflected XSS — 검색어가 그 응답에만 즉시 반영
app.get('/api/xss/lv1/vulnerable', (req, res) => {
  res.json({ html: xssVulnerable(req.query.q || '') });
});
app.get('/api/xss/lv1/patched', (req, res) => {
  res.json({ html: xssPatched(req.query.q || '') });
});

// Lv.2~4, Challenge — Stored XSS (댓글이 서버 메모리에 쌓여 모든 열람자에게 노출)
const STORED_LEVELS = ['lv2', 'lv3', 'lv4', 'challenge'];

function requireStoredLevel(req, res, next) {
  if (!STORED_LEVELS.includes(req.params.level)) {
    return res.status(404).json({ error: 'unknown level' });
  }
  next();
}

app.get('/api/xss/:level/comments', requireStoredLevel, (req, res) => {
  const level = req.params.level;
  // lv4는 "패치된 버전"이라 저장된 원본과 무관하게 조회 시 항상 이스케이프해서 돌려줌
  res.json(level === 'lv4' ? listCommentsEscaped(level) : listComments(level));
});

app.post('/api/xss/:level/comments', requireStoredLevel, (req, res) => {
  const { comment = '' } = req.body || {};
  const level = req.params.level;
  if (level === 'lv2') return res.json(postCommentVulnerable(level, comment));
  if (level === 'lv4') return res.json(postCommentPatched(level, comment));
  // lv3, challenge — 둘 다 script 블랙리스트 필터만 적용
  return res.json(postCommentFiltered(level, comment));
});

// 실습 중 댓글함을 비우고 다시 시작할 때 사용 (학습 편의용)
app.post('/api/xss/:level/reset', requireStoredLevel, (req, res) => {
  res.json(resetComments(req.params.level));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Web Security Lab backend running: http://localhost:${PORT}`);
});

// ===== IDOR 가상 데이터베이스 =====
const IDOR_DB = {
  1: { id: 1, username: 'guest_user', role: 'guest', email: 'guest@lab.com', secret: '일반 사용자의 평범한 메모입니다.' },
  2: { id: 2, username: 'alice', role: 'user', email: 'alice@lab.com', secret: '앨리스의 개인 다이어리: 프로젝트 일정 정리' },
  3: { id: 3, username: 'admin', role: 'administrator', email: 'admin@lab.com', secret: '🏆 [FLAG] FLAG{idor_access_control_bypass_success} - 시스템 최고 관리자 계정 정보' }
};

// 1. 취약한 IDOR API (권한 검증 없이 요청한 id 그대로 반환)
app.get('/api/idor/user', (req, res) => {
  const userId = req.query.id;
  
  if (!IDOR_DB[userId]) {
    return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
  }
  
  // 취약점 포인트: 현재 로그인한 사용자가 누구든 상관없이 요청된 id 데이터를 그대로 응답
  res.json(IDOR_DB[userId]);
});

// 2. 패치된 안전한 IDOR API (세션 또는 토큰 권한 검증 포함)
app.get('/api/idor/secure-user', (req, res) => {
  const requestedId = req.query.id;
  
  // 가정: 현재 로그인된 사용자의 실제 ID는 세션(여기서는 편의상 고정값 1)이라고 가정
  const loggedInUserId = '1'; 

  // 방어 코드: 내 ID와 요청한 ID가 다르면 접근 차단
  if (requestedId !== loggedInUserId) {
    return res.status(403).json({ error: "접근 권한이 없습니다. (본인 정보만 조회 가능)" });
  }

  res.json(IDOR_DB[loggedInUserId]);
});