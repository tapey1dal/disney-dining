'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const FAMILY_PASSWORD = process.env.FAMILY_PASSWORD || '';
const SECRET = process.env.SESSION_SECRET || FAMILY_PASSWORD + '-session';
if (!FAMILY_PASSWORD) { console.error('FAMILY_PASSWORD is not set'); process.exit(1); }

/* ---------- storage: Postgres on Render, JSON file for local testing ---------- */
let store;
if (process.env.DATABASE_URL) {
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === 'off' ? false : { rejectUnauthorized: false } });
  store = {
    async init() {
      await pool.query('CREATE TABLE IF NOT EXISTS picks (rid TEXT, uid TEXT, name TEXT, ts BIGINT, PRIMARY KEY (rid, uid))');
      await pool.query('CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY, rid TEXT, uid TEXT, name TEXT, text TEXT, ts BIGINT)');
    },
    async state() {
      const p = (await pool.query('SELECT rid, uid, name FROM picks ORDER BY ts')).rows;
      const n = (await pool.query('SELECT id, rid, uid, name, text, ts FROM notes ORDER BY ts')).rows;
      return { picks: p, notes: n.map(r => ({ ...r, ts: Number(r.ts) })) };
    },
    async togglePick(rid, uid, name) {
      const d = await pool.query('DELETE FROM picks WHERE rid=$1 AND uid=$2', [rid, uid]);
      if (!d.rowCount) await pool.query('INSERT INTO picks (rid, uid, name, ts) VALUES ($1,$2,$3,$4)', [rid, uid, name, Date.now()]);
    },
    async addNote(n) { await pool.query('INSERT INTO notes (id, rid, uid, name, text, ts) VALUES ($1,$2,$3,$4,$5,$6)', [n.id, n.rid, n.uid, n.name, n.text, n.ts]); },
    async delNote(id, uid) { await pool.query('DELETE FROM notes WHERE id=$1 AND uid=$2', [id, uid]); },
    async countNotes(uid) { return Number((await pool.query('SELECT COUNT(*) FROM notes WHERE uid=$1', [uid])).rows[0].count); }
  };
} else {
  const file = path.join(__dirname, 'data.json');
  let d = { picks: [], notes: [] };
  try { d = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) {}
  const save = () => fs.writeFileSync(file, JSON.stringify(d));
  store = {
    async init() {},
    async state() { return JSON.parse(JSON.stringify(d)); },
    async togglePick(rid, uid, name) {
      const i = d.picks.findIndex(p => p.rid === rid && p.uid === uid);
      if (i >= 0) d.picks.splice(i, 1); else d.picks.push({ rid, uid, name, ts: Date.now() });
      save();
    },
    async addNote(n) { d.notes.push(n); save(); },
    async delNote(id, uid) { d.notes = d.notes.filter(n => !(n.id === id && n.uid === uid)); save(); },
    async countNotes(uid) { return d.notes.filter(n => n.uid === uid).length; }
  };
}

/* ---------- sessions ---------- */
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeToken(u) { const b = Buffer.from(JSON.stringify(u)).toString('base64url'); return b + '.' + sign(b); }
function readToken(t) {
  if (!t) return null;
  const [b, sig] = t.split('.');
  if (!b || !sig) return null;
  const good = sign(b);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try { return JSON.parse(Buffer.from(b, 'base64url').toString()); } catch (e) { return null; }
}
function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(c => { const i = c.indexOf('='); if (i > 0) o[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim()); });
  return o;
}
function who(req) { return readToken(cookies(req).fam); }
const slug = s => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 30);
function passOK(p) {
  const a = crypto.createHash('sha256').update(String(p)).digest();
  const b = crypto.createHash('sha256').update(FAMILY_PASSWORD).digest();
  return crypto.timingSafeEqual(a, b);
}

/* ---------- login throttle ---------- */
const tries = new Map();
function throttled(ip) {
  const now = Date.now(); const t = (tries.get(ip) || []).filter(x => now - x < 60000);
  tries.set(ip, t); return t.length >= 8;
}
function noteTry(ip) { const t = tries.get(ip) || []; t.push(Date.now()); tries.set(ip, t); }

/* ---------- http ---------- */
const INDEX = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
function send(res, code, obj, extra) {
  const body = JSON.stringify(obj);
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, extra || {}));
  res.end(body);
}
function readBody(req) {
  return new Promise((ok, no) => {
    let s = ''; req.on('data', c => { s += c; if (s.length > 20000) { no(new Error('big')); req.destroy(); } });
    req.on('end', () => { try { ok(s ? JSON.parse(s) : {}); } catch (e) { no(e); } });
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = req.url.split('?')[0];
    if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Robots-Tag': 'noindex', 'X-Content-Type-Options': 'nosniff' });
      return res.end(INDEX);
    }
    if (url === '/healthz') return send(res, 200, { ok: true });
    if (!url.startsWith('/api/')) { res.writeHead(404); return res.end('Not found'); }

    if (url === '/api/login' && req.method === 'POST') {
      const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
      if (throttled(ip)) return send(res, 429, { error: 'slow down' });
      const b = await readBody(req);
      const name = String(b.name || '').trim().replace(/\s+/g, ' ').slice(0, 30);
      if (!name || !slug(name) || !passOK(b.password || '')) { noteTry(ip); return send(res, 401, { error: 'auth' }); }
      const u = { id: slug(name), name };
      const secure = (req.headers['x-forwarded-proto'] || '') === 'https' ? '; Secure' : '';
      return send(res, 200, u, { 'Set-Cookie': 'fam=' + encodeURIComponent(makeToken(u)) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000' + secure });
    }
    if (url === '/api/logout' && req.method === 'POST') return send(res, 200, { ok: true }, { 'Set-Cookie': 'fam=; Path=/; HttpOnly; Max-Age=0' });

    const me = who(req);
    if (!me) return send(res, 401, { error: 'auth' });

    if (url === '/api/me' && req.method === 'GET') return send(res, 200, me);
    if (url === '/api/state' && req.method === 'GET') {
      const s = await store.state();
      const picks = {}, notes = {}, names = {};
      s.picks.forEach(p => { (picks[p.rid] = picks[p.rid] || []).push(p.uid); names[p.uid] = p.name; });
      s.notes.forEach(n => { (notes[n.rid] = notes[n.rid] || []).push({ docId: n.id, uid: n.uid, text: n.text, ts: n.ts }); names[n.uid] = n.name; });
      return send(res, 200, { picks, notes, names });
    }
    if (url === '/api/pick' && req.method === 'POST') {
      const b = await readBody(req); const rid = String(b.rid || '').slice(0, 120);
      if (!rid) return send(res, 400, { error: 'bad' });
      await store.togglePick(rid, me.id, me.name); return send(res, 200, { ok: true });
    }
    if (url === '/api/note' && req.method === 'POST') {
      const b = await readBody(req); const rid = String(b.rid || '').slice(0, 120); const text = String(b.text || '').trim().slice(0, 600);
      if (!rid || !text) return send(res, 400, { error: 'bad' });
      if ((await store.countNotes(me.id)) >= 500) return send(res, 400, { error: 'limit' });
      await store.addNote({ id: crypto.randomUUID(), rid, uid: me.id, name: me.name, text, ts: Date.now() });
      return send(res, 200, { ok: true });
    }
    if (url.startsWith('/api/note/') && req.method === 'DELETE') {
      await store.delNote(decodeURIComponent(url.slice(10)), me.id); return send(res, 200, { ok: true });
    }
    send(res, 404, { error: 'nope' });
  } catch (e) { console.error(e); send(res, 500, { error: 'server' }); }
});

store.init().then(() => server.listen(PORT, () => console.log('Dining board on ' + PORT)));
