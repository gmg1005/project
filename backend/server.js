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
  checkCookieTheft,
  XSS_CHALLENGE_FLAG,
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

// ========== ModSecurity(WAF) 시뮬레이션 ==========
// 실제 Apache + ModSecurity + OWASP CRS(Core Rule Set)를 설치하는 대신,
// CRS가 쓰는 핵심 탐지 로직(구조적 패턴 매칭 — 토큰 치환이 아니라 'OR 1=1', UNION SELECT,
// <script>, 이벤트 핸들러 속성 같은 "공격 형태 자체"를 봄)을 그대로 재현한 미들웨어입니다.
// scenario.html에서 설명한 것과 동일하게: SQLi/XSS는 요청 자체에 패턴이 드러나서 여기서 잡히지만,
// IDOR 라우트(/api/idor/*)에는 이 미들웨어를 아예 연결하지 않습니다 — 요청이 문법적으로 정상이라
// 패턴 매칭으로는 원천적으로 탐지가 안 되기 때문입니다 (실제 ModSecurity도 마찬가지입니다).
let wafEnabled = false;

const CRS_RULES = [
  // SQL Injection — OWASP CRS 942xxx 계열에 대응
  { id: '942100', type: 'SQL Injection', re: /'\s*[\w\d]+\s*'\s*=\s*'\s*[\w\d]+\s*'/i },      // 'x'='x' 형태의 항상-참 조건(튜톨로지)
  { id: '942260', type: 'SQL Injection', re: /\b(or|and)\b\s+['"]?\d/i },                       // OR 1=1 / AND 1=1 류의 불리언 조건
  { id: '942270', type: 'SQL Injection', re: /union(\s|\/\*[\s\S]*?\*\/)+select/i },            // UNION SELECT
  { id: '942360', type: 'SQL Injection', re: /(--|#|\/\*)/ },                                   // SQL 주석으로 쿼리 뒷부분을 잘라내는 패턴
  { id: '942190', type: 'SQL Injection', re: /\bsubstr\s*\(/i },                                 // Blind SQLi에서 쓰는 SUBSTR
  // XSS — OWASP CRS 941xxx 계열에 대응
  { id: '941100', type: 'XSS', re: /<script[\s>]/i },                                           // <script> 태그
  { id: '941160', type: 'XSS', re: /on\w+\s*=/i },                                               // onerror=, onload= 같은 이벤트 핸들러 속성
  { id: '941150', type: 'XSS', re: /javascript\s*:/i },                                          // javascript: URI 스킴
];

function scanForAttack(value) {
  if (typeof value !== 'string') return null;
  for (const rule of CRS_RULES) {
    const m = rule.re.exec(value);
    if (m) return { rule, matched: m[0], field: value };
  }
  return null;
}

function wafMiddleware(req, res, next) {
  if (!wafEnabled) return next();
  const sources = [req.body || {}, req.query || {}];
  for (const src of sources) {
    for (const key of Object.keys(src)) {
      const hit = scanForAttack(src[key]);
      if (hit) {
        return res.status(403).json({
          blocked: true,
          rule: hit.rule.id,
          type: hit.rule.type,
          field: hit.field,
          matched: hit.matched,
          regex: hit.rule.re.toString(),
          message: `WAF 차단됨 — ${hit.rule.type} 공격 패턴이 탐지되었습니다 (OWASP CRS Rule ${hit.rule.id}). 애플리케이션에 도달하기 전에 ModSecurity가 요청을 차단했습니다.`,
        });
      }
    }
  }
  next();
}

// SQLi/XSS 라우트에만 적용 — IDOR(/api/idor/*)에는 의도적으로 적용하지 않음
app.use('/api/sqli', wafMiddleware);
app.use('/api/xss', wafMiddleware);

app.get('/api/waf/status', (req, res) => res.json({ enabled: wafEnabled }));
app.post('/api/waf/toggle', (req, res) => {
  wafEnabled = !!(req.body && req.body.enabled);
  res.json({ enabled: wafEnabled });
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

// Challenge Stage 2 — Stage 1(script 필터 우회로 스크립트 실행)만으로는 FLAG가 안 나옵니다.
// 그 실행된 스크립트로 "document.cookie 값을 외부로 전송"하는 실제 피해 패턴까지 만들어야
// 진짜 FLAG가 공개됩니다. (샌드박스 iframe이라 실제로 쿠키를 훔치진 않고, 패턴만 판정합니다)
app.post('/api/xss/challenge/steal', (req, res) => {
  const { comment = '' } = req.body || {};
  const { filtered, stolen } = checkCookieTheft(comment);
  res.json({ filtered, stolen, flag: stolen ? XSS_CHALLENGE_FLAG : null });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Web Security Lab backend running: http://localhost:${PORT}`);
});

// ==========================================
// ========== IDOR 5단계 확장 구현 API ==========
// ==========================================
const IDOR_USERS_DB = {
  1: { id: 1, username: 'sincheonchae', role: 'student', credit: '50,000 KRW', flag: 'FLAG{idor_lv1_basic_success}' },
  2: { id: 2, username: 'victim_admin', role: 'admin', credit: '1,000,000 KRW', flag: 'FLAG{idor_lv2_header_bypass}' },
  3: { id: 3, username: 'manager_lee', role: 'manager', credit: '500,000 KRW', flag: 'FLAG{idor_lv3_multi_parameter}' }
};

const IDOR_ACCOUNTS_DB = {
  '1001': { owner: 'sincheonchae', balance: '50,000 KRW' },
  '1002': { owner: 'victim_admin', balance: '5,000,000 KRW', flag: 'FLAG{idor_lv3_multi_parameter}' }
};

// Lv.1: 기본 파라미터 조작
app.get('/api/idor/level1', (req, res) => {
  const targetId = req.query.id || 1;
  const user = IDOR_USERS_DB[targetId];
  if (!user) {
    return res.status(404).json({ status: 'error', message: '대상을 찾을 수 없습니다.' });
  }
  res.json({ level: 1, mission: 'URL 파라미터 조작', status: 'success', data: user });
});

// Lv.2: 헤더 우회 (X-User-Role: admin)
app.get('/api/idor/level2', (req, res) => {
  const targetId = req.query.id || 2;
  const roleHeader = req.headers['x-user-role'];

  if (roleHeader && roleHeader.toLowerCase() === 'admin') {
    const user = IDOR_USERS_DB[targetId] || IDOR_USERS_DB[2];
    return res.json({ level: 2, mission: '헤더 우회 성공', bypassed: true, status: 'success', data: user, flag: user.flag });
  }

  res.json({ level: 2, mission: '헤더 우회 실패', bypassed: false, status: 'restricted', message: '권한이 부족합니다. 관리자 헤더(X-User-Role: admin)를 주입해보세요.', data: IDOR_USERS_DB[1] });
});

// Lv.3: 다중 객체 참조 (계좌번호)
app.get('/api/idor/level3', (req, res) => {
  const accountNo = req.query.account_no || '1001';
  const targetAccount = IDOR_ACCOUNTS_DB[accountNo] || IDOR_ACCOUNTS_DB['1001'];
  res.json({ level: 3, mission: '다중 객체 식별자 우회', status: 'success', account_number: accountNo, data: targetAccount });
});

// Lv.4: Base64 인코딩 우회 (Mg== -> ID 2)
app.get('/api/idor/level4', (req, res) => {
  const encodedId = req.query.encoded_id || 'MQ==';
  try {
    let decodedId = Buffer.from(encodedId, 'base64').toString('ascii').trim();
    const user = IDOR_USERS_DB[decodedId];

    if (decodedId === '2' && user) {
      return res.json({ level: 4, mission: 'Base64 인코딩 우회 성공', status: 'success', encoded_id: encodedId, decoded_id: decodedId, data: user, flag: 'FLAG{idor_lv4_encoded_bypass}' });
    }
  } catch (e) {}

  res.json({ level: 4, mission: 'Base64 인코딩 우회 실패', status: 'fail', message: '올바른 Base64 인코딩 ID(예: Mg==)를 입력하세요.' });
});

// Lv.5 (Challenge): 최종 플래그 검증
app.post('/api/idor/level5/verify', (req, res) => {
  const { submitted_flag } = req.body || {};
  const validFlags = [
    'FLAG{idor_lv1_basic_success}',
    'FLAG{idor_lv2_header_bypass}',
    'FLAG{idor_lv3_multi_parameter}',
    'FLAG{idor_lv4_encoded_bypass}'
  ];

  if (submitted_flag && (validFlags.includes(submitted_flag) || submitted_flag.includes('FLAG{'))) {
    res.json({ level: 5, status: 'congratulations', message: '축하합니다! 모든 IDOR 5단계 챌린지를 완벽하게 클리어하고 과정을 수료하셨습니다.' });
  } else {
    res.status(400).json({ level: 5, status: 'failed', message: '올바른 플래그 형식이 아니거나 틀렸습니다. 각 레벨에서 획득한 플래그를 확인하세요.' });
  }
});