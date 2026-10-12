import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { hashPassword, verifyPassword } from './password.js';
import * as v from './validate.js';
import { HttpError, parseId, readBody } from './validate.js';

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const MAX_NOTES_PER_USER = 500;
const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const randomToken = () => crypto.randomBytes(32).toString('base64url');

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// Fixed-window in-memory attempt counter.
function createLimiter({ max, windowMs }) {
  const hits = new Map();
  const live = (key, now) => {
    const e = hits.get(key);
    if (e && e.resetAt <= now) hits.delete(key);
    return hits.get(key);
  };
  return {
    retryAfter(key) {
      const now = Date.now();
      const e = live(key, now);
      return e && e.count >= max ? Math.ceil((e.resetAt - now) / 1000) : 0;
    },
    hit(key) {
      const now = Date.now();
      if (hits.size > 10000) for (const k of hits.keys()) live(k, now);
      const e = live(key, now) ?? { count: 0, resetAt: now + windowMs };
      e.count += 1;
      hits.set(key, e);
    },
    reset(key) {
      hits.delete(key);
    },
  };
}

export function createApp({
  db,
  cookieSecure = false,
  sessionTtlMs = 60 * 60 * 1000,
  trustProxy = false,
  loginLimit = { max: 5, windowMs: 15 * 60 * 1000 },
  registerLimit = { max: 20, windowMs: 60 * 60 * 1000 },
}) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', trustProxy);

  const cookieName = cookieSecure ? '__Host-sid' : 'sid';
  const cookieOpts = { httpOnly: true, sameSite: 'strict', secure: cookieSecure, path: '/' };
  const loginLimiter = createLimiter(loginLimit);
  const registerLimiter = createLimiter(registerLimit);
  let dummyHash; // verified against when the username is unknown, to keep timing uniform

  const q = {
    userByName: db.prepare('SELECT id, username, password_hash, role FROM users WHERE username = ?'),
    userById: db.prepare('SELECT id, username, role, created_at FROM users WHERE id = ?'),
    insertUser: db.prepare('INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)'),
    listUsers: db.prepare('SELECT id, username, role, created_at FROM users ORDER BY id'),
    setRole: db.prepare('UPDATE users SET role = ? WHERE id = ?'),
    deleteUser: db.prepare('DELETE FROM users WHERE id = ?'),

    sessionByHash: db.prepare(
      `SELECT s.token_hash, s.csrf_token, u.id, u.username, u.role
         FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ? AND s.expires_at > ?`,
    ),
    insertSession: db.prepare('INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    deleteUserSessions: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
    deleteExpiredSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),

    listNotes: db.prepare(
      'SELECT id, title, content, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY updated_at DESC, id DESC',
    ),
    countNotes: db.prepare('SELECT COUNT(*) AS n FROM notes WHERE user_id = ?'),
    getNote: db.prepare('SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?'),
    insertNote: db.prepare('INSERT INTO notes (user_id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'),
    updateNote: db.prepare('UPDATE notes SET title = ?, content = ?, updated_at = ? WHERE id = ? AND user_id = ?'),
    deleteNote: db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?'),

    adminListNotes: db.prepare(
      `SELECT n.id, n.title, n.content, n.created_at, n.updated_at, u.id AS owner_id, u.username AS owner_username
         FROM notes n JOIN users u ON u.id = n.user_id
        ORDER BY n.updated_at DESC, n.id DESC`,
    ),
    adminDeleteNote: db.prepare('DELETE FROM notes WHERE id = ?'),
  };

  const userView = (u) => ({ id: u.id, username: u.username, role: u.role });
  const adminUserView = (u) => ({ ...userView(u), createdAt: u.created_at });
  const noteView = (n) => ({
    id: n.id,
    title: n.title,
    content: n.content,
    createdAt: n.created_at,
    updatedAt: n.updated_at,
  });
  const adminNoteView = (n) => ({ ...noteView(n), ownerId: n.owner_id, ownerUsername: n.owner_username });

  async function createUser(username, password, role) {
    const hash = await hashPassword(password);
    try {
      const { lastInsertRowid } = q.insertUser.run(username, hash, role, new Date().toISOString());
      return q.userById.get(lastInsertRowid);
    } catch (err) {
      if (String(err.message).includes('UNIQUE')) throw new HttpError(409, 'Username is already taken');
      throw err;
    }
  }

  function readSessionCookie(req) {
    for (const part of (req.headers.cookie ?? '').split(';')) {
      const i = part.indexOf('=');
      if (i !== -1 && part.slice(0, i).trim() === cookieName) return part.slice(i + 1).trim();
    }
    return null;
  }

  function requireAuth(req, _res, next) {
    if (!req.user) throw new HttpError(401, 'Authentication required');
    next();
  }

  function requireAdmin(req, _res, next) {
    if (req.user.role !== 'admin') throw new HttpError(403, 'Forbidden');
    next();
  }

  app.use((_req, res, next) => {
    res.set({
      'Content-Security-Policy':
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    });
    next();
  });

  const api = express.Router();
  api.use(express.json({ limit: '50kb' }));

  api.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');

    // The user and role are re-read from the database on every request, so
    // role changes and account deletion take effect immediately.
    const token = readSessionCookie(req);
    const row = token ? q.sessionByHash.get(sha256(token), Date.now()) : undefined;
    if (row) {
      req.user = { id: row.id, username: row.username, role: row.role };
      req.session = { tokenHash: row.token_hash, csrfToken: row.csrf_token };
    }

    if (UNSAFE_METHODS.has(req.method)) {
      const origin = req.headers.origin;
      if (origin !== undefined) {
        let host = null;
        try {
          host = new URL(origin).host;
        } catch {}
        if (host !== req.headers.host) throw new HttpError(403, 'Cross-origin request rejected');
      }
    }
    next();
  });

  // --- Authentication (no CSRF token exists before login) ---

  api.post('/auth/register', async (req, res) => {
    const { username, password } = readBody(req, { username: v.username, password: v.newPassword });
    const wait = registerLimiter.retryAfter(req.ip);
    if (wait) {
      res.set('Retry-After', String(wait));
      throw new HttpError(429, 'Too many registrations, try again later');
    }
    registerLimiter.hit(req.ip);
    // Self-registration always creates a student; the role is never client-supplied.
    const user = await createUser(username, password, 'student');
    res.status(201).json({ user: userView(user) });
  });

  api.post('/auth/login', async (req, res) => {
    const { username, password } = readBody(req, { username: v.username, password: v.loginPassword });
    const key = `${req.ip}|${username.toLowerCase()}`;
    const wait = loginLimiter.retryAfter(key);
    if (wait) {
      res.set('Retry-After', String(wait));
      throw new HttpError(429, 'Too many failed login attempts, try again later');
    }

    const user = q.userByName.get(username);
    dummyHash ??= await hashPassword(randomToken());
    const ok = await verifyPassword(password, user?.password_hash ?? dummyHash);
    if (!user || !ok) {
      loginLimiter.hit(key);
      throw new HttpError(401, 'Invalid username or password');
    }
    loginLimiter.reset(key);

    // Always issue a fresh session id on login (prevents session fixation).
    if (req.session) q.deleteSession.run(req.session.tokenHash);
    q.deleteExpiredSessions.run(Date.now());
    const token = randomToken();
    const csrfToken = randomToken();
    q.insertSession.run(sha256(token), user.id, csrfToken, Date.now() + sessionTtlMs);
    res.cookie(cookieName, token, { ...cookieOpts, maxAge: sessionTtlMs });
    res.json({ user: userView(user), csrfToken });
  });

  // --- Everything below requires a session, and a CSRF token for writes ---

  api.use(requireAuth);
  api.use((req, _res, next) => {
    if (UNSAFE_METHODS.has(req.method) && !safeEqual(req.get('x-csrf-token') ?? '', req.session.csrfToken)) {
      throw new HttpError(403, 'Invalid CSRF token');
    }
    next();
  });

  api.get('/auth/me', (req, res) => {
    res.json({ user: req.user, csrfToken: req.session.csrfToken });
  });

  api.post('/auth/logout', (req, res) => {
    q.deleteSession.run(req.session.tokenHash);
    res.clearCookie(cookieName, cookieOpts);
    res.status(204).end();
  });

  // --- Notes: every query is scoped to the session user ---

  const noteSpec = { title: v.title, content: v.content };

  api.get('/notes', (req, res) => {
    res.json({ notes: q.listNotes.all(req.user.id).map(noteView) });
  });

  api.post('/notes', (req, res) => {
    const { title, content } = readBody(req, noteSpec);
    if (q.countNotes.get(req.user.id).n >= MAX_NOTES_PER_USER) {
      throw new HttpError(409, `Note limit reached (${MAX_NOTES_PER_USER})`);
    }
    const now = new Date().toISOString();
    const { lastInsertRowid } = q.insertNote.run(req.user.id, title, content, now, now);
    res.status(201).json({ note: noteView(q.getNote.get(lastInsertRowid, req.user.id)) });
  });

  // A note owned by someone else is indistinguishable from a missing one.
  api.get('/notes/:id', (req, res) => {
    const note = q.getNote.get(parseId(req.params.id), req.user.id);
    if (!note) throw new HttpError(404, 'Note not found');
    res.json({ note: noteView(note) });
  });

  api.put('/notes/:id', (req, res) => {
    const id = parseId(req.params.id);
    const { title, content } = readBody(req, noteSpec);
    const { changes } = q.updateNote.run(title, content, new Date().toISOString(), id, req.user.id);
    if (!changes) throw new HttpError(404, 'Note not found');
    res.json({ note: noteView(q.getNote.get(id, req.user.id)) });
  });

  api.delete('/notes/:id', (req, res) => {
    const { changes } = q.deleteNote.run(parseId(req.params.id), req.user.id);
    if (!changes) throw new HttpError(404, 'Note not found');
    res.status(204).end();
  });

  // --- Admin ---

  const admin = express.Router();
  admin.use(requireAdmin);

  admin.get('/users', (_req, res) => {
    res.json({ users: q.listUsers.all().map(adminUserView) });
  });

  admin.post('/users', async (req, res) => {
    const { username, password, role } = readBody(req, {
      username: v.username,
      password: v.newPassword,
      role: v.role,
    });
    res.status(201).json({ user: adminUserView(await createUser(username, password, role)) });
  });

  admin.patch('/users/:id/role', (req, res) => {
    const id = parseId(req.params.id);
    const { role } = readBody(req, { role: v.role });
    // Admins cannot change their own role, so at least one admin always remains.
    if (id === req.user.id) throw new HttpError(403, 'You cannot change your own role');
    if (!q.setRole.run(role, id).changes) throw new HttpError(404, 'User not found');
    q.deleteUserSessions.run(id);
    res.json({ user: adminUserView(q.userById.get(id)) });
  });

  admin.delete('/users/:id', (req, res) => {
    const id = parseId(req.params.id);
    if (id === req.user.id) throw new HttpError(403, 'You cannot delete your own account');
    if (!q.deleteUser.run(id).changes) throw new HttpError(404, 'User not found');
    res.status(204).end();
  });

  admin.get('/notes', (_req, res) => {
    res.json({ notes: q.adminListNotes.all().map(adminNoteView) });
  });

  admin.delete('/notes/:id', (req, res) => {
    if (!q.adminDeleteNote.run(parseId(req.params.id)).changes) throw new HttpError(404, 'Note not found');
    res.status(204).end();
  });

  api.use('/admin', admin);

  api.use(() => {
    throw new HttpError(404, 'Not found');
  });

  app.use('/api', api);
  app.use(express.static(PUBLIC_DIR));
  app.use((_req, res) => res.status(404).type('text').send('Not found'));

  // Never leak stack traces or internal messages to the client.
  app.use((err, _req, res, _next) => {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request body too large' });
    if (err.status >= 400 && err.status < 500) return res.status(400).json({ error: 'Malformed request' });
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}
