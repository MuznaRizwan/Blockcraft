'use strict';
// Blockcraft API server: accounts, two-step sign-in, profiles, game results and saved worlds.
// Requires Node 22.13+ (built-in node:sqlite). No npm packages needed.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
let DatabaseSync;
try {
  ({ DatabaseSync } = require('node:sqlite'));
} catch {
  console.error(`Blockcraft needs Node 22.13 or newer, but this is ${process.version}. Use a newer Node image (for example node:22).`);
  process.exit(1);
}

const PORT = Number(process.env.PORT) || 3000;
const SECURE = process.env.COOKIE_SECURE === '1'; // set to 1 when served over HTTPS
const TRUST_PROXY = process.env.TRUST_PROXY === '1'; // set to 1 behind Fly.io or another proxy that sets the client address
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const N = 48, H = 24, CELLS = N * N * H, LAYER = N * N;
const MAX_WORLDS = 8, MAX_EDITS = 20000, BODY_MAX = 300 * 1024;
const BLOCKS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
const ITER = 210000, SESSION_MS = 12 * 3600e3;
const CTRL = /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202F\uFEFF]/g;
const A32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

fs.mkdirSync(DATA_DIR, { recursive: true });
const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));

// ---------- keys and encryption (TOTP secrets are encrypted at rest) ----------
const KEY = (() => {
  if (process.env.BLOCKCRAFT_KEY) return crypto.scryptSync(process.env.BLOCKCRAFT_KEY, 'blockcraft-v1', 32);
  const f = path.join(DATA_DIR, '.master-key');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(32).toString('base64'), { mode: 0o600 });
  return Buffer.from(fs.readFileSync(f, 'utf8'), 'base64');
})();
function seal(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), ct].map((b) => b.toString('base64')).join('.');
}
function open(s) {
  const [iv, tag, ct] = s.split('.').map((x) => Buffer.from(x, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

// ---------- passwords and one-time codes ----------
const hashPw = (pw, salt) => crypto.pbkdf2Sync(pw, salt, ITER, 32, 'sha256').toString('base64');
const DUMMY_SALT = Buffer.alloc(16, 7); // used for unknown emails so timing does not reveal accounts
function same(a, b) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function b32encode(buf) {
  let v = 0, n = 0, o = '';
  for (const b of buf) { v = (v << 8) | b; n += 8; while (n >= 5) { o += A32[(v >>> (n - 5)) & 31]; n -= 5; } }
  if (n > 0) o += A32[(v << (5 - n)) & 31];
  return o;
}
function b32decode(t) {
  let v = 0, n = 0; const o = [];
  for (const ch of t) { v = (v << 5) | A32.indexOf(ch); n += 5; if (n >= 8) { o.push((v >>> (n - 8)) & 255); n -= 8; } }
  return Buffer.from(o);
}
function totpAt(secret, step) {
  const c = Buffer.alloc(8);
  c.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', b32decode(secret)).update(c).digest();
  const o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}
// Returns the matched time step, or 0. Steps at or before lastStep are rejected (no code reuse).
function checkTotp(secret, code, lastStep) {
  const s = Math.floor(Date.now() / 30000);
  for (const d of [-1, 0, 1]) if (s + d > lastStep && totpAt(secret, s + d) === code) return s + d;
  return 0;
}

// ---------- database ----------
const db = new DatabaseSync(path.join(DATA_DIR, 'blockcraft.db'));
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT NOT NULL UNIQUE,
  phone TEXT NOT NULL,
  pw_salt TEXT NOT NULL,
  pw_hash TEXT NOT NULL,
  totp_enc TEXT NOT NULL,
  last_step INTEGER NOT NULL DEFAULT 0,
  fails INTEGER NOT NULL DEFAULT 0,
  lock_until INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS profiles (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  play_secs INTEGER NOT NULL DEFAULT 0,
  placed INTEGER NOT NULL DEFAULT 0,
  broken INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS games (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  round INTEGER NOT NULL,
  score INTEGER NOT NULL,
  over INTEGER NOT NULL,
  created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS games_user ON games(user_id, created);
CREATE TABLE IF NOT EXISTS worlds (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  edits TEXT NOT NULL,
  saved INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pending (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  user_id INTEGER,
  data TEXT NOT NULL,
  expires INTEGER NOT NULL,
  fails INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires INTEGER NOT NULL
);
`);

const tx = (fn) => {
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
};
let lastSweep = 0;
function sweep() {
  const t = Date.now();
  if (t - lastSweep < 60e3) return;
  lastSweep = t;
  db.prepare('DELETE FROM pending WHERE expires < ?').run(t);
  db.prepare('DELETE FROM sessions WHERE expires < ?').run(t);
}

// ---------- helpers ----------
const rid = (n) => crypto.randomBytes(n).toString('base64url');
const sha = (s) => crypto.createHash('sha256').update(s).digest('base64url');
const clean = (v, max) => String(v == null ? '' : v).normalize('NFKC').replace(CTRL, '').trim().slice(0, max);
function httpErr(status, message) { return Object.assign(new Error(message), { status }); }

function validate({ username, email, phone, password }) {
  if ([username, email, phone, password].some((x) => typeof x !== 'string')) throw httpErr(400, 'Every field is required.');
  const u = clean(username, 40);
  const e = clean(email, 254).toLowerCase();
  const p = clean(phone, 40).replace(/[\s\-()]/g, '').replace(/^\+/, '');
  const pw = password.normalize('NFKC').replace(CTRL, '');
  if (!/^[A-Za-z0-9_]{3,20}$/.test(u)) throw httpErr(400, 'Use 3 to 20 letters, numbers or underscores.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)) throw httpErr(400, 'Enter a valid email address.');
  if (!/^\d{10,15}$/.test(p)) throw httpErr(400, 'Enter 10 to 15 digits including the country code.');
  if (pw.length > 128) throw httpErr(400, 'Password must be 128 characters or fewer.');
  if (pw.length < 12 || !/[A-Z]/.test(pw) || !/[a-z]/.test(pw) || !/\d/.test(pw) || !/[^A-Za-z0-9]/.test(pw))
    throw httpErr(400, 'Password must be 12+ characters with uppercase, lowercase, a number and a special character.');
  return { username: u, email: e, phone: p, password: pw };
}

function makePending(kind, uid, data, ttl) {
  const id = rid(24);
  db.prepare('INSERT INTO pending (id, kind, user_id, data, expires, fails) VALUES (?, ?, ?, ?, ?, 0)')
    .run(id, kind, uid, JSON.stringify(data), Date.now() + ttl);
  return id;
}
function takePending(id, kind) {
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{20,60}$/.test(id)) return null;
  return db.prepare('SELECT * FROM pending WHERE id = ? AND kind = ? AND expires > ?').get(id, kind, Date.now()) || null;
}
const dropPending = (id) => db.prepare('DELETE FROM pending WHERE id = ?').run(id);

function penalize(u) {
  const fails = u.fails + 1;
  const lock = fails >= 5 ? Date.now() + Math.min(15 * 60e3, 30e3 * 2 ** (fails - 5)) : 0;
  db.prepare('UPDATE users SET fails = ?, lock_until = ? WHERE id = ?').run(fails, lock, u.id);
}

const RATE_SCALE = Number(process.env.RATE_SCALE) || 1; // tests raise this; keep 1 in production
const hits = new Map();
function limited(ip, bucket, max) {
  const k = bucket + '|' + ip, t = Date.now();
  const a = (hits.get(k) || []).filter((x) => t - x < 60e3);
  a.push(t);
  hits.set(k, a);
  return a.length > max * RATE_SCALE;
}

const tokenOf = (req) => {
  const m = /(?:^|;\s*)bc_session=([A-Za-z0-9_-]{20,80})/.exec(req.headers.cookie || '');
  return m ? m[1] : null;
};
function currentUser(req) {
  const t = tokenOf(req);
  if (!t) return null;
  return db.prepare('SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires > ?')
    .get(sha(t), Date.now()) || null;
}
function startSession(res, uid, username) {
  const token = rid(32);
  db.prepare('INSERT INTO sessions (token, user_id, expires) VALUES (?, ?, ?)').run(sha(token), uid, Date.now() + SESSION_MS);
  return send(res, 200, { user: { username } }, {
    'Set-Cookie': `bc_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${SECURE ? '; Secure' : ''}`,
  });
}

function checkEdits(list) {
  if (!Array.isArray(list) || list.length > MAX_EDITS) throw httpErr(400, 'Invalid world data.');
  const seen = new Set(), out = [];
  for (const e of list) {
    if (!Array.isArray(e) || e.length !== 2) throw httpErr(400, 'Invalid world data.');
    const [i, v] = e;
    if (!Number.isInteger(i) || i < 0 || i >= CELLS || !BLOCKS.includes(v) || seen.has(i)) throw httpErr(400, 'Invalid world data.');
    if (i < LAYER && v === 0) throw httpErr(400, "The bottom layer can't be broken.");
    seen.add(i);
    out.push([i, v]);
  }
  return out;
}

function baseHeaders() {
  const h = {
    'Content-Security-Policy': CSP,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  };
  if (SECURE) h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  return h;
}
function send(res, status, obj, extra = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    ...baseHeaders(),
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    ...extra,
  });
  res.end(body);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0, tooBig = false;
    req.on('data', (d) => { size += d.length; if (size > BODY_MAX) tooBig = true; else chunks.push(d); });
    req.on('end', () => {
      if (tooBig) return reject(httpErr(413, 'Request is too large.'));
      if (!chunks.length) return resolve({});
      try {
        const x = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(x && typeof x === 'object' && !Array.isArray(x) ? x : {});
      } catch { reject(httpErr(400, 'Invalid request.')); }
    });
    req.on('error', () => reject(httpErr(400, 'Invalid request.')));
  });
}

// ---------- API routes ----------
async function api(req, res, url) {
  const p = url.pathname, m = req.method;
  const ip = (TRUST_PROXY && (req.headers['fly-client-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0].trim())) || req.socket.remoteAddress || 'unknown';
  if (m !== 'GET') {
    const origin = req.headers.origin;
    if (origin && origin !== `${SECURE ? 'https' : 'http'}://${req.headers.host}`) throw httpErr(403, 'Cross-site request blocked.');
  }
  if ((m === 'POST' || m === 'PUT') && !/^application\/json\b/i.test(req.headers['content-type'] || '')) throw httpErr(415, 'Send JSON.');
  sweep();
  const me = currentUser(req);
  const body = m === 'POST' || m === 'PUT' ? await readJson(req) : {};
  const need = () => { if (!me) throw httpErr(401, 'Please log in.'); return me; };
  const codeOf = (c) => (typeof c === 'string' ? c.trim() : '');

  if (m === 'GET' && p === '/api/me') return send(res, 200, { user: me ? { username: me.username } : null });

  // Sign-up step 1: validate, hash, and hold the account until the authenticator code is confirmed.
  if (m === 'POST' && p === '/api/signup') {
    if (limited(ip, 'signup', 10)) throw httpErr(429, 'Too many sign-up attempts. Wait a minute.');
    const v = validate(body);
    if (db.prepare('SELECT 1 FROM users WHERE username = ? OR email = ?').get(v.username, v.email))
      throw httpErr(409, 'That username or email is already registered.');
    const salt = crypto.randomBytes(16);
    const secret = b32encode(crypto.randomBytes(20));
    const pending = makePending('signup', null, {
      username: v.username, email: v.email, phone: v.phone,
      pw_salt: salt.toString('base64'), pw_hash: hashPw(v.password, salt), totp: seal(secret),
    }, 10 * 60e3);
    return send(res, 200, { pending, secret });
  }

  // Sign-up step 2: confirm the authenticator code, then create the account.
  if (m === 'POST' && p === '/api/signup/confirm') {
    if (limited(ip, 'confirm', 30)) throw httpErr(429, 'Too many attempts. Wait a minute.');
    const row = takePending(body.pending, 'signup');
    if (!row) throw httpErr(400, 'This sign-up has expired. Start again.');
    if (row.fails >= 5) { dropPending(row.id); throw httpErr(400, 'Too many wrong codes. Start sign-up again.'); }
    const code = codeOf(body.code);
    if (!/^\d{6}$/.test(code)) throw httpErr(400, 'Enter the 6-digit code.');
    const d = JSON.parse(row.data);
    const step = checkTotp(open(d.totp), code, 0);
    if (!step) {
      db.prepare('UPDATE pending SET fails = fails + 1 WHERE id = ?').run(row.id);
      throw httpErr(401, 'That code is not valid or has expired.');
    }
    const uid = tx(() => {
      let r;
      try {
        r = db.prepare(`INSERT INTO users (username, email, phone, pw_salt, pw_hash, totp_enc, last_step, created)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(d.username, d.email, d.phone, d.pw_salt, d.pw_hash, d.totp, step, Date.now());
      } catch (e) {
        if (/UNIQUE/.test(String(e.message))) throw httpErr(409, 'That username or email is already registered.');
        throw e;
      }
      const id = Number(r.lastInsertRowid);
      db.prepare('INSERT INTO profiles (user_id) VALUES (?)').run(id);
      dropPending(row.id);
      return id;
    });
    return startSession(res, uid, d.username);
  }

  // Sign-in step 1: check the password (with lockout), then hold the sign-in for the code.
  if (m === 'POST' && p === '/api/login') {
    if (limited(ip, 'login', 20)) throw httpErr(429, 'Too many sign-in attempts. Wait a minute.');
    const email = clean(body.email, 254).toLowerCase();
    const password = (typeof body.password === 'string' ? body.password : '').normalize('NFKC').replace(CTRL, '');
    const u = email ? db.prepare('SELECT * FROM users WHERE email = ?').get(email) : null;
    if (u && u.lock_until > Date.now())
      throw httpErr(429, `Too many attempts. Try again in ${Math.ceil((u.lock_until - Date.now()) / 1000)} seconds.`);
    const h = hashPw(password, u ? Buffer.from(u.pw_salt, 'base64') : DUMMY_SALT);
    if (!u || !same(h, u.pw_hash)) {
      if (u) penalize(u);
      throw httpErr(401, 'Invalid email or password.');
    }
    // The failure counter is only cleared after a full sign-in, so a stolen password cannot reset the lockout.
    return send(res, 200, { pending: makePending('login', u.id, {}, 5 * 60e3) });
  }

  // Sign-in step 2: check the authenticator code (codes cannot be reused).
  if (m === 'POST' && p === '/api/login/confirm') {
    if (limited(ip, 'confirm', 30)) throw httpErr(429, 'Too many attempts. Wait a minute.');
    const row = takePending(body.pending, 'login');
    if (!row) throw httpErr(400, 'This sign-in has expired. Log in again.');
    if (row.fails >= 5) { dropPending(row.id); throw httpErr(400, 'Too many wrong codes. Log in again.'); }
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);
    if (!u) throw httpErr(400, 'This sign-in has expired. Log in again.');
    if (u.lock_until > Date.now())
      throw httpErr(429, `Too many attempts. Try again in ${Math.ceil((u.lock_until - Date.now()) / 1000)} seconds.`);
    const code = codeOf(body.code);
    if (!/^\d{6}$/.test(code)) throw httpErr(400, 'Enter the 6-digit code.');
    const step = checkTotp(open(u.totp_enc), code, u.last_step);
    if (!step) {
      db.prepare('UPDATE pending SET fails = fails + 1 WHERE id = ?').run(row.id);
      penalize(u);
      throw httpErr(401, 'That code is not valid or has expired.');
    }
    tx(() => {
      db.prepare('UPDATE users SET last_step = ?, fails = 0, lock_until = 0 WHERE id = ?').run(step, u.id);
      dropPending(row.id);
    });
    return startSession(res, u.id, u.username);
  }

  if (m === 'POST' && p === '/api/logout') {
    const t = tokenOf(req);
    if (t) db.prepare('DELETE FROM sessions WHERE token = ?').run(sha(t));
    return send(res, 200, { ok: true }, { 'Set-Cookie': `bc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${SECURE ? '; Secure' : ''}` });
  }

  if (m === 'GET' && p === '/api/profile') {
    const u = need();
    const stats = db.prepare('SELECT play_secs AS secs, placed, broken FROM profiles WHERE user_id = ?').get(u.id) || { secs: 0, placed: 0, broken: 0 };
    const best = db.prepare('SELECT round, score FROM games WHERE user_id = ? ORDER BY round DESC, score DESC LIMIT 1').get(u.id) || null;
    const history = db.prepare('SELECT round, score, created AS date FROM games WHERE user_id = ? AND over = 1 ORDER BY created DESC LIMIT 5').all(u.id);
    return send(res, 200, { stats, best, history });
  }

  if (m === 'POST' && p === '/api/stats') {
    const u = need();
    const num = (k, max) => {
      const x = body[k] === undefined ? 0 : body[k];
      if (!Number.isInteger(x) || x < 0 || x > max) throw httpErr(400, 'Invalid stats.');
      return x;
    };
    const secs = num('secs', 600), placed = num('placed', 5000), broken = num('broken', 5000);
    db.prepare('UPDATE profiles SET play_secs = play_secs + ?, placed = placed + ?, broken = broken + ? WHERE user_id = ?')
      .run(secs, placed, broken, u.id);
    return send(res, 200, { ok: true });
  }

  if (m === 'POST' && p === '/api/games') {
    const u = need();
    const { round, score, over } = body;
    if (!Number.isInteger(round) || round < 1 || round > 10000 || !Number.isInteger(score) || score < 0 || score > 1e9 || typeof over !== 'boolean')
      throw httpErr(400, 'Invalid game result.');
    db.prepare('INSERT INTO games (user_id, round, score, over, created) VALUES (?, ?, ?, ?, ?)')
      .run(u.id, round, score, over ? 1 : 0, Date.now());
    return send(res, 200, { ok: true });
  }

  if (p === '/api/worlds' && m === 'GET') {
    const u = need();
    const worlds = db.prepare('SELECT id, name, saved, json_array_length(edits) AS changes FROM worlds WHERE user_id = ? ORDER BY saved DESC').all(u.id);
    return send(res, 200, { worlds });
  }

  const wm = /^\/api\/worlds\/([A-Za-z0-9_-]{4,40})$/.exec(p);
  if (wm) {
    const u = need(), id = wm[1];
    const row = db.prepare('SELECT * FROM worlds WHERE id = ? AND user_id = ?').get(id, u.id);
    if (m === 'GET') {
      if (!row) throw httpErr(404, 'World not found.');
      return send(res, 200, { id: row.id, name: row.name, saved: row.saved, edits: JSON.parse(row.edits) });
    }
    if (m === 'DELETE') {
      db.prepare('DELETE FROM worlds WHERE id = ? AND user_id = ?').run(id, u.id);
      return send(res, 200, { ok: true });
    }
    if (m === 'PUT') {
      const edits = checkEdits(body.edits);
      const name = clean(typeof body.name === 'string' ? body.name : '', 24).replace(/[^A-Za-z0-9 _-]/g, '').trim() || 'World';
      if (!row) {
        if (db.prepare('SELECT 1 FROM worlds WHERE id = ?').get(id)) throw httpErr(409, 'Could not save that world. Try again.');
        const n = db.prepare('SELECT COUNT(*) AS n FROM worlds WHERE user_id = ?').get(u.id).n;
        if (n >= MAX_WORLDS) throw httpErr(409, `You can keep ${MAX_WORLDS} worlds. Delete one first.`);
        db.prepare('INSERT INTO worlds (id, user_id, name, edits, saved) VALUES (?, ?, ?, ?, ?)')
          .run(id, u.id, name, JSON.stringify(edits), Date.now());
      } else {
        db.prepare('UPDATE worlds SET name = ?, edits = ?, saved = ? WHERE id = ? AND user_id = ?')
          .run(name, JSON.stringify(edits), Date.now(), id, u.id);
      }
      return send(res, 200, { id, name, changes: edits.length });
    }
  }
  throw httpErr(404, 'Not found.');
}

function staticFile(p, res) {
  if (p === '/healthz') return send(res, 200, { ok: true });
  if (p === '/' || p === '/index.html') {
    res.writeHead(200, { ...baseHeaders(), 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    return res.end(INDEX_HTML);
  }
  send(res, 404, { error: 'Not found.' });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && !url.pathname.startsWith('/api/')) return staticFile(url.pathname, res);
    await api(req, res, url);
  } catch (err) {
    if (err.status) return send(res, err.status, { error: err.message });
    console.error(err);
    send(res, 500, { error: 'Something went wrong. Please try again.' });
  }
});
server.requestTimeout = 15000;
server.listen(PORT, '0.0.0.0', () => console.log(`Blockcraft running on http://localhost:${PORT} (data in ${DATA_DIR})`));
module.exports = { server, db };
