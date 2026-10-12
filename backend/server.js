const express = require('express');
const path = require('path');
const {
  vulnerableLogin,
  filteredLogin,
  patchedLogin,
  vulnerableProduct,
  patchedProduct,
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
  res.json(vulnerableLogin(username, password));
});
app.post('/api/sqli/lv1/patched', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  res.json(patchedLogin(username, password));
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
app.post('/api/sqli/lv3/vulnerable', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  res.json(filteredLogin(username, password));
});

// Lv.4 패치된 버전 — Prepared Statement (Lv.1 patched와 동일 로직, 레벨 구분용 별도 경로)
app.post('/api/sqli/lv4', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  res.json(patchedLogin(username, password));
});

// Challenge — Lv.3과 같은 'or' 필터, 힌트 없이 admin 로그인 우회가 목표
app.post('/api/sqli/challenge/vulnerable', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  res.json(filteredLogin(username, password));
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
