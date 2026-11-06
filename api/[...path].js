'use strict';
// Blockcraft API as one Vercel serverless function (catch-all route: /api/*).
// Database: Supabase (Postgres), reached through Supabase's connection pooler. Every database call is async, so every one is awaited.
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const pbkdf2 = promisify(crypto.pbkdf2);

const N = 48, H = 24, CELLS = N * N * H, LAYER = N * N;
const MAX_WORLDS = 8, MAX_EDITS = 20000, BODY_MAX = 300 * 1024;
const BLOCKS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
const ITER = 210000, SESSION_MS = 12 * 3600e3;
const CTRL = /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202F\uFEFF]/g;
const A32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const SECURE = process.env.COOKIE_SECURE !== '0'; // Vercel is always HTTPS; set COOKIE_SECURE=0 only for plain-http local testing
// Set REQUIRE_OTP=0 in Vercel to let people sign up and log in with just a password (no authenticator code).
const REQUIRE_OTP = process.env.REQUIRE_OTP !== '0';
const RATE_SCALE = Number(process.env.RATE_SCALE) || 1; // tests raise this; keep 1 in production
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || '').split(',').map((x) => x.trim().replace(/\/$/, '')).filter(Boolean);

// ---------- configuration is read lazily, so a missing setting gives a clear log line ----------
let _db, _key, _ready;
// 'postgres' is an ES module, so it is loaded with import() (works from CommonJS). Hence database() returns a promise.
function database() {
  if (!_db) {
    _db = connect().catch((e) => { _db = null; throw e; });
  }
  return _db;
}
async function connect() {
  {
    // Use the Supabase *transaction pooler* string (port 6543): Dashboard > Connect > Transaction pooler.
    // The Vercel + Supabase integration provides the same thing as POSTGRES_URL.
    const raw = process.env.DATABASE_URL || process.env.POSTGRES_URL;
    if (!raw) throw new Error('DATABASE_URL is not set');
    const u = new URL(raw);
    u.searchParams.delete('supa'); // added by the Vercel integration; the driver would forward it to the server as an unknown setting
    const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
    const postgres = (await import('postgres')).default;
    return postgres(u.toString(), {
      prepare: false,      // required by the transaction pooler (no prepared statements)
      max: 1,              // one connection per function instance; the pooler does the real pooling
      idle_timeout: 20,
      connect_timeout: 10,
      onnotice: () => {},  // hide harmless "already exists, skipping" notices from CREATE ... IF NOT EXISTS
      ssl: local ? false : 'require',
      // bigint columns hold millisecond timestamps and ids; return them as plain numbers (safe below 2^53)
      types: { bigint: { to: 20, from: [20], serialize: (x) => String(x), parse: (x) => Number(x) } },
    });
  }
}
function key() {
  if (!_key) {
    const s = process.env.BLOCKCRAFT_KEY;
    if (!s || s.length < 16) throw new Error('BLOCKCRAFT_KEY must be set to a secret of 16+ characters');
    _key = crypto.scryptSync(s, 'blockcraft-v1', 32);
  }
  return _key;
}

// Row Level Security is switched on with no policies: Supabase exposes the public schema through its
// REST API, and this locks that door. This server connects as the postgres role, which bypasses RLS.
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT NOT NULL,
  pw_salt TEXT NOT NULL,
  pw_hash TEXT NOT NULL,
  totp_enc TEXT NOT NULL,
  last_step BIGINT NOT NULL DEFAULT 0,
  fails INTEGER NOT NULL DEFAULT 0,
  lock_until BIGINT NOT NULL DEFAULT 0,
  created BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users (lower(username));
CREATE TABLE IF NOT EXISTS profiles (
  user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  play_secs BIGINT NOT NULL DEFAULT 0,
  placed BIGINT NOT NULL DEFAULT 0,
  broken BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS games (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  round INTEGER NOT NULL,
  score BIGINT NOT NULL,
  over SMALLINT NOT NULL,
  created BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS games_user ON games(user_id, created);
CREATE TABLE IF NOT EXISTS worlds (
  id TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  edits TEXT NOT NULL,
  saved BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  user_id BIGINT,
  data TEXT NOT NULL,
  expires BIGINT NOT NULL,
  fails INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS rate (
  k TEXT PRIMARY KEY,
  n INTEGER NOT NULL,
  reset BIGINT NOT NULL
);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE games ENABLE ROW LEVEL SECURITY;
ALTER TABLE worlds ENABLE ROW LEVEL SECURITY;
ALTER TABLE pending ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate ENABLE ROW LEVEL SECURITY;
`;
// Creates the tables on first use. Once they exist you can set AUTO_MIGRATE=0 to skip this step on cold starts.
function ready() {
  if (process.env.AUTO_MIGRATE === '0') return Promise.resolve();
  if (!_ready) _ready = database().then((db) => db.unsafe(SCHEMA)).then(() => undefined).catch((e) => { _ready = null; throw e; });
  return _ready;
}

// ---------- tiny database helpers ----------
// Queries below are written with ? placeholders; this turns them into Postgres $1, $2, ...
const pg = (s) => { let i = 0; return s.replace(/\?/g, () => '$' + (++i)); };
const run = async (sql, args = []) => (await database()).unsafe(pg(sql), args);
const rows = (sql, args) => run(sql, args);
const one = async (sql, args) => (await rows(sql, args))[0] || null;
// Runs fn inside one all-or-nothing transaction. fn receives a query function q(sql, args).
const transaction = async (fn) => (await database()).begin((tx) => fn((sql, args = []) => tx.unsafe(pg(sql), args)));
const batch = (stmts) => transaction(async (q) => { for (const s of stmts) await q(s.sql, s.args); });

let lastSweep = 0;
async function sweep() {
  const t = Date.now();
  if (t - lastSweep < 60e3) return;
  lastSweep = t;
  await batch([
    { sql: 'DELETE FROM pending WHERE expires < ?', args: [t] },
    { sql: 'DELETE FROM sessions WHERE expires < ?', args: [t] },
    { sql: 'DELETE FROM rate WHERE reset < ?', args: [t] },
  ]);
}

// ---------- encryption of authenticator keys ----------
function seal(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const ct = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), ct].map((b) => b.toString('base64')).join('.');
}
function open(s) {
  const [iv, tag, ct] = s.split('.').map((x) => Buffer.from(x, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', key(), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

// ---------- passwords and one-time codes ----------
const hashPw = async (pw, salt) => (await pbkdf2(pw, salt, ITER, 32, 'sha256')).toString('base64'); // async, so it does not block the function
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
  console.log('in totpAt');
  const c = Buffer.alloc(8);
  c.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', b32decode(secret)).update(c).digest();
  const o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}
// Returns the matched time step, or 0. Steps at or before lastStep are rejected (no code reuse).
function checkTotp(secret, code, lastStep) {
  console.log('in checkTotp');
  const s = Math.floor(Date.now() / 30000);
  for (const d of [-1, 0, 1]) if (s + d > lastStep && totpAt(secret, s + d) === code) return s + d;
  return 0;
}

// ---------- helpers ----------
const rid = (n) => crypto.randomBytes(n).toString('base64url');
const sha = (s) => crypto.createHash('sha256').update(s).digest('base64url');
const clean = (v, max) => String(v == null ? '' : v).normalize('NFKC').replace(CTRL, '').trim().slice(0, max);
function httpErr(status, message) { return Object.assign(new Error(message), { status }); }
const isUniqueViolation = (e) => e && e.code === '23505'; // Postgres "unique_violation"

function validate({ username, email, phone, password }) {
  console.log('in validate');
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

// Creates the account, its profile row and (optionally) removes the pending sign-up, all in one transaction.
async function createAccount(d, step, pendingId) {
  console.log('in createAccount');
  try {
    return await transaction(async (q) => {
      const r = await q(
        'INSERT INTO users (username, email, phone, pw_salt, pw_hash, totp_enc, last_step, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id',
        [d.username, d.email, d.phone, d.pw_salt, d.pw_hash, d.totp, step, Date.now()],
      );
      await q('INSERT INTO profiles (user_id) VALUES (?)', [r[0].id]);
      if (pendingId) await q('DELETE FROM pending WHERE id = ?', [pendingId]);
      return Number(r[0].id);
    });
  } catch (e) {
    if (isUniqueViolation(e)) throw httpErr(409, 'That username or email is already registered.');
    throw e;
  }
}

async function makePending(kind, uid, data, ttl) {
  console.log('in makePending', kind, uid, data, ttl);
  const id = rid(24);
  await run('INSERT INTO pending (id, kind, user_id, data, expires, fails) VALUES (?, ?, ?, ?, ?, 0)', [id, kind, uid, JSON.stringify(data), Date.now() + ttl]);
  return id;
}
async function takePending(id, kind) {
  console.log('in takePending');
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{20,60}$/.test(id)) return null;
  return one('SELECT * FROM pending WHERE id = ? AND kind = ? AND expires > ?', [id, kind, Date.now()]);
}
const dropPending = (id) => run('DELETE FROM pending WHERE id = ?', [id]);

async function penalize(u) {
  const fails = Number(u.fails) + 1;
  const lock = fails >= 5 ? Date.now() + Math.min(15 * 60e3, 30e3 * 2 ** (fails - 5)) : 0;
  await run('UPDATE users SET fails = ?, lock_until = ? WHERE id = ?', [fails, lock, u.id]);
}

// Rate limit kept in the database, because every serverless call may run on a different instance.
async function limited(ip, bucket, max) {
  const t = Date.now();
  const r = await one(
    `INSERT INTO rate (k, n, reset) VALUES (?, 1, ?)
     ON CONFLICT (k) DO UPDATE SET
       n = CASE WHEN rate.reset < ? THEN 1 ELSE rate.n + 1 END,
       reset = CASE WHEN rate.reset < ? THEN ?::bigint ELSE rate.reset END
     RETURNING n`,
    [bucket + '|' + ip, t + 60e3, t, t, t + 60e3],
  );
  return Number(r.n) > max * RATE_SCALE;
}
// Vercel overwrites x-forwarded-for, so its first value is the real visitor address.
const ipOf = (req) => String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.headers['x-real-ip'] || (req.socket && req.socket.remoteAddress) || 'unknown';

const tokenOf = (req) => {
  const m = /(?:^|;\s*)bc_session=([A-Za-z0-9_-]{20,80})/.exec(req.headers.cookie || '');
  return m ? m[1] : null;
};
async function currentUser(req) {
  console.log('in currentUser');
  const t = tokenOf(req);
  if (!t) {
    console.log('no token t');
    return null;
  }
  const r = await one('SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires > ?', [sha(t), Date.now()]);
  if (r) {
    console.log('successfully get user session information', u.id, u.username);
  } else {
    console.log('unable to get user session information');
  }
  return r ? { id: Number(r.id), username: String(r.username) } : null;
}
async function startSession(res, uid, username) {
  console.log('in startSession');
  const token = rid(32);
  await run('INSERT INTO sessions (token, user_id, expires) VALUES (?, ?, ?)', [sha(token), uid, Date.now() + SESSION_MS]);
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

function send(res, status, obj, extra = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    ...(SECURE ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } : {}),
    ...extra,
  });
  res.end(body);
}

// Vercel parses JSON bodies for us (req.body). Reading it can throw on malformed JSON.
function bodyOf(req) {
  if (req.method !== 'POST' && req.method !== 'PUT') return {};
  if (Number(req.headers['content-length'] || 0) > BODY_MAX) throw httpErr(413, 'Request is too large.');
  let b;
  try { b = req.body; } catch { throw httpErr(400, 'Invalid request.'); }
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch { throw httpErr(400, 'Invalid request.'); } }
  return b && typeof b === 'object' && !Array.isArray(b) && !Buffer.isBuffer(b) ? b : {};
}

// ---------- routes ----------
async function route(req, res) {
  console.log('REQUEST METHOD:', req.method);
  console.log('REQUEST URL:', req.url);
  
  const p = new URL(req.url, 'http://localhost').pathname.replace(/\/+$/, '') || '/';
  const m = req.method, ip = ipOf(req);

  console.log('[API REQUEST 1]:', m, p);
  
  // Handle both Vercel URL formats.
  if (!p.startsWith('/api/')) {
    p = '/api' + (p.startsWith('/') ? p : '/' + p);
  }
  
  console.log('[API REQUEST 2]:', m, p);

  if (m !== 'GET' && m !== 'HEAD') {
    const origin = req.headers.origin;
    const self = `${SECURE ? 'https' : 'http'}://${req.headers.host}`;
    if (origin && origin !== self && !ALLOWED_ORIGINS.includes(origin)) throw httpErr(403, 'Cross-site request blocked.');
  }
  if ((m === 'POST' || m === 'PUT') && !/^application\/json\b/i.test(req.headers['content-type'] || '')) throw httpErr(415, 'Send JSON.');

  if (m === 'GET' && p === '/api/healthz') return send(res, 200, { ok: true });

  // A visitor with no session cookie is simply logged out. Answer at once, without waking the database.
  if (m === 'GET' && p === '/api/me' && !tokenOf(req)) return send(res, 200, { user: null });

  key();            // fail early, with a clear log line, if the secret is missing
  await ready();    // make sure the tables exist
  await sweep();
  const me = await currentUser(req);
  const body = bodyOf(req);
  const need = () => { if (!me) throw httpErr(401, 'Please log in.'); return me; };
  const codeOf = (c) => (typeof c === 'string' ? c.trim() : '');

  if (m === 'GET' && p === '/api/me') return send(res, 200, { user: me ? { username: me.username } : null });

  // Sign-up step 1: validate, hash, and hold the account until the authenticator code is confirmed.
  if (m === 'POST' && p === '/api/signup') {
    if (await limited(ip, 'signup', 10)) throw httpErr(429, 'Too many sign-up attempts. Wait a minute.');
    const v = validate(body);
    if (await one('SELECT 1 AS x FROM users WHERE lower(username) = lower(?) OR email = ?', [v.username, v.email]))
      throw httpErr(409, 'That username or email is already registered.');
    const salt = crypto.randomBytes(16);
    const secret = b32encode(crypto.randomBytes(20));
    if (!REQUIRE_OTP) { // password only: create the account now and sign the person in
      const uid = await createAccount({
        username: v.username, email: v.email, phone: v.phone,
        pw_salt: salt.toString('base64'), pw_hash: await hashPw(v.password, salt), totp: seal(secret),
      }, 0, null);
      return startSession(res, uid, v.username);
    }
    const pending = await makePending('signup', null, {
      username: v.username, email: v.email, phone: v.phone,
      pw_salt: salt.toString('base64'), pw_hash: await hashPw(v.password, salt), totp: seal(secret),
    }, 10 * 60e3);
    return send(res, 200, { pending, secret });
  }

  // Sign-up step 2: confirm the authenticator code, then create the account.
  if (m === 'POST' && p === '/api/signup/confirm') {
    console.log('in /api/signup/confirm');
    if (await limited(ip, 'confirm', 30)) throw httpErr(429, 'Too many attempts. Wait a minute.');
    const row = await takePending(body.pending, 'signup');
    if (!row) throw httpErr(400, 'This sign-up has expired. Start again.');
    if (Number(row.fails) >= 5) { await dropPending(row.id); throw httpErr(400, 'Too many wrong codes. Start sign-up again.'); }
    const code = codeOf(body.code);
    if (!/^\d{6}$/.test(code)) throw httpErr(400, 'Enter the 6-digit code.');
    const d = JSON.parse(row.data);
    const step = checkTotp(open(d.totp), code, 0);
    if (!step) {
      await run('UPDATE pending SET fails = fails + 1 WHERE id = ?', [row.id]);
      throw httpErr(401, 'That code is not valid or has expired.');
    }
    const uid = await createAccount(d, step, row.id);
    return startSession(res, uid, d.username);
  }

  // Sign-in step 1: check the password (with lockout), then hold the sign-in for the code.
  if (m === 'POST' && p === '/api/login') {
    console.log('in /api/login');
    if (await limited(ip, 'login', 20)) throw httpErr(429, 'Too many sign-in attempts. Wait a minute.');
    const email = clean(body.email, 254).toLowerCase();
    const password = (typeof body.password === 'string' ? body.password : '').normalize('NFKC').replace(CTRL, '');
    const u = email ? await one('SELECT * FROM users WHERE email = ?', [email]) : null;
    if (u && Number(u.lock_until) > Date.now())
      throw httpErr(429, `Too many attempts. Try again in ${Math.ceil((Number(u.lock_until) - Date.now()) / 1000)} seconds.`);
    const h = await hashPw(password, u ? Buffer.from(u.pw_salt, 'base64') : DUMMY_SALT);
    if (!u || !same(h, u.pw_hash)) {
      if (u) await penalize(u);
      throw httpErr(401, 'Invalid email or password.');
    }
    if (!REQUIRE_OTP) { // password only: finish the sign-in now
      await run('UPDATE users SET fails = 0, lock_until = 0 WHERE id = ?', [u.id]);
      return startSession(res, Number(u.id), String(u.username));
    }
    // The failure counter is only cleared after a full sign-in, so a stolen password cannot reset the lockout.
    return send(res, 200, { pending: await makePending('login', Number(u.id), {}, 5 * 60e3) });
  }

  // Sign-in step 2: check the authenticator code (codes cannot be reused).
  if (m === 'POST' && p === '/api/login/confirm') {
    console.log('in /api/login/confirm');
    if (await limited(ip, 'confirm', 30)) throw httpErr(429, 'Too many attempts. Wait a minute.');
    const row = await takePending(body.pending, 'login');
    if (!row) throw httpErr(400, 'This sign-in has expired. Log in again.');
    if (Number(row.fails) >= 5) { await dropPending(row.id); throw httpErr(400, 'Too many wrong codes. Log in again.'); }
    const u = await one('SELECT * FROM users WHERE id = ?', [row.user_id]);
    if (!u) throw httpErr(400, 'This sign-in has expired. Log in again.');
    if (Number(u.lock_until) > Date.now())
      throw httpErr(429, `Too many attempts. Try again in ${Math.ceil((Number(u.lock_until) - Date.now()) / 1000)} seconds.`);
    const code = codeOf(body.code);
    if (!/^\d{6}$/.test(code)) throw httpErr(400, 'Enter the 6-digit code.');
    const step = checkTotp(open(u.totp_enc), code, Number(u.last_step));
    if (!step) {
      await run('UPDATE pending SET fails = fails + 1 WHERE id = ?', [row.id]);
      await penalize(u);
      throw httpErr(401, 'That code is not valid or has expired.');
    }
    await batch([
      { sql: 'UPDATE users SET last_step = ?, fails = 0, lock_until = 0 WHERE id = ?', args: [step, u.id] },
      { sql: 'DELETE FROM pending WHERE id = ?', args: [row.id] },
    ]);
    return startSession(res, Number(u.id), String(u.username));
  }

  if (m === 'POST' && p === '/api/logout') {
    const t = tokenOf(req);
    if (t) await run('DELETE FROM sessions WHERE token = ?', [sha(t)]);
    return send(res, 200, { ok: true }, { 'Set-Cookie': `bc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${SECURE ? '; Secure' : ''}` });
  }

  if (m === 'GET' && p === '/api/profile') {
    const u = need();
    const s = await one('SELECT play_secs, placed, broken FROM profiles WHERE user_id = ?', [u.id]);
    const b = await one('SELECT round, score FROM games WHERE user_id = ? ORDER BY round DESC, score DESC LIMIT 1', [u.id]);
    const h = await rows('SELECT round, score, created FROM games WHERE user_id = ? AND over = 1 ORDER BY created DESC LIMIT 5', [u.id]);
    return send(res, 200, {
      stats: { secs: s ? Number(s.play_secs) : 0, placed: s ? Number(s.placed) : 0, broken: s ? Number(s.broken) : 0 },
      best: b ? { round: Number(b.round), score: Number(b.score) } : null,
      history: h.map((g) => ({ round: Number(g.round), score: Number(g.score), date: Number(g.created) })),
    });
  }

  if (m === 'POST' && p === '/api/stats') {
    const u = need();
    const num = (k, max) => {
      const x = body[k] === undefined ? 0 : body[k];
      if (!Number.isInteger(x) || x < 0 || x > max) throw httpErr(400, 'Invalid stats.');
      return x;
    };
    const secs = num('secs', 600), placed = num('placed', 5000), broken = num('broken', 5000);
    await run('UPDATE profiles SET play_secs = play_secs + ?, placed = placed + ?, broken = broken + ? WHERE user_id = ?', [secs, placed, broken, u.id]);
    return send(res, 200, { ok: true });
  }

  if (m === 'POST' && p === '/api/games') {
    const u = need();
    const { round, score, over } = body;
    if (!Number.isInteger(round) || round < 1 || round > 10000 || !Number.isInteger(score) || score < 0 || score > 1e9 || typeof over !== 'boolean')
      throw httpErr(400, 'Invalid game result.');
    await run('INSERT INTO games (user_id, round, score, over, created) VALUES (?, ?, ?, ?, ?)', [u.id, round, score, over ? 1 : 0, Date.now()]);
    return send(res, 200, { ok: true });
  }

  if (p === '/api/worlds' && m === 'GET') {
    const u = need();
    const list = await rows('SELECT id, name, saved, jsonb_array_length(edits::jsonb) AS changes FROM worlds WHERE user_id = ? ORDER BY saved DESC', [u.id]);
    return send(res, 200, { worlds: list.map((w) => ({ id: String(w.id), name: String(w.name), saved: Number(w.saved), changes: Number(w.changes) })) });
  }

  const wm = /^\/api\/worlds\/([A-Za-z0-9_-]{4,40})$/.exec(p);
  if (wm) {
    const u = need(), id = wm[1];
    const row = await one('SELECT * FROM worlds WHERE id = ? AND user_id = ?', [id, u.id]);
    if (m === 'GET') {
      if (!row) throw httpErr(404, 'World not found.');
      return send(res, 200, { id: String(row.id), name: String(row.name), saved: Number(row.saved), edits: JSON.parse(row.edits) });
    }
    if (m === 'DELETE') {
      await run('DELETE FROM worlds WHERE id = ? AND user_id = ?', [id, u.id]);
      return send(res, 200, { ok: true });
    }
    if (m === 'PUT') {
      const edits = checkEdits(body.edits);
      const name = clean(typeof body.name === 'string' ? body.name : '', 24).replace(/[^A-Za-z0-9 _-]/g, '').trim() || 'World';
      if (!row) {
        if (await one('SELECT 1 AS x FROM worlds WHERE id = ?', [id])) throw httpErr(409, 'Could not save that world. Try again.');
        const n = await one('SELECT COUNT(*) AS n FROM worlds WHERE user_id = ?', [u.id]);
        if (Number(n.n) >= MAX_WORLDS) throw httpErr(409, `You can keep ${MAX_WORLDS} worlds. Delete one first.`);
        await run('INSERT INTO worlds (id, user_id, name, edits, saved) VALUES (?, ?, ?, ?, ?)', [id, u.id, name, JSON.stringify(edits), Date.now()]);
      } else {
        await run('UPDATE worlds SET name = ?, edits = ?, saved = ? WHERE id = ? AND user_id = ?', [name, JSON.stringify(edits), Date.now(), id, u.id]);
      }
      return send(res, 200, { id, name, changes: edits.length });
    }
  }
  // throw httpErr(404, 'Not found.');
  return send(res, 404, {
    error: 'API endpoint not found.',
    method: m,
    path: p
  });
}

module.exports = async (req, res) => {
  try {
    await route(req, res);
  } catch (err) {
    if (err && err.status) return send(res, err.status, { error: err.message });
    console.error(err); // shows up in the Vercel function logs
    send(res, 500, { error: 'Something went wrong. Please try again.' });
  }
};
