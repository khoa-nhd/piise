const crypto = require('node:crypto');
const express = require('express');
const { hashPassword, verifyPassword } = require('./passwords');

const COOKIE = 'sid';
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_FAILED_LOGINS = 10;
const LOCKOUT_MS = 15 * 60 * 1000;

// Verified against when the username is unknown so both paths take similar time.
const DUMMY_HASH = hashPassword(crypto.randomBytes(16).toString('hex'));

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

function readSessionToken(req) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === COOKIE) return rest.join('=');
  }
  return null;
}

function cookieHeader(token, maxAgeSeconds) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSeconds}${secure}`;
}

function requireAuth(db) {
  const findUser = db.prepare(
    `SELECT u.id, u.username, u.full_name, u.role
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ?`
  );
  return (req, res, next) => {
    const token = readSessionToken(req);
    const user = token && findUser.get(sha256(token), Date.now());
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    req.user = user;
    next();
  };
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

function authRouter(db) {
  const router = express.Router();
  const failures = new Map(); // ip -> { count, resetAt }

  router.post('/login', (req, res) => {
    const { username, password } = req.body ?? {};
    if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const now = Date.now();
    let entry = failures.get(req.ip);
    if (entry && entry.resetAt <= now) {
      failures.delete(req.ip);
      entry = undefined;
    }
    if (entry && entry.count >= MAX_FAILED_LOGINS) {
      return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
    }

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
    const ok = verifyPassword(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok) {
      if (entry) entry.count += 1;
      else failures.set(req.ip, { count: 1, resetAt: now + LOCKOUT_MS });
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    failures.delete(req.ip);

    db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now);
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(
      sha256(token),
      user.id,
      now + SESSION_MS
    );
    res.setHeader('Set-Cookie', cookieHeader(token, SESSION_MS / 1000));
    res.json({
      user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role },
    });
  });

  router.post('/logout', (req, res) => {
    const token = readSessionToken(req);
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
    res.setHeader('Set-Cookie', cookieHeader('', 0));
    res.status(204).end();
  });

  router.get('/me', requireAuth(db), (req, res) => res.json({ user: req.user }));

  return router;
}

module.exports = { authRouter, requireAuth, requireAdmin };
