const express = require('express');
const db = require('../db');
const v = require('../validate');
const { createUser } = require('../users');
const { hashPassword, verifyPassword, createSession, destroySession, toUser, requireAuth } = require('../auth');

const router = express.Router();

// Failed logins per ip+username, to slow down password guessing.
const MAX_FAILURES = 10;
const WINDOW_MS = 15 * 60 * 1000;
const failures = new Map();

// Verified against when the username does not exist, so both cases take the same time.
const dummyHash = hashPassword('not-a-real-password');

router.post('/register', async (req, res) => {
  const body = req.body ?? {};
  const user = await createUser({
    username: v.username(body.username),
    password: v.password(body.password),
    fullName: v.fullName(body.fullName),
  });
  res.status(201).json({ token: createSession(user.id), user: toUser(user) });
});

router.post('/login', async (req, res) => {
  const body = req.body ?? {};
  if (typeof body.username !== 'string' || typeof body.password !== 'string') {
    throw new v.HttpError(400, 'username and password are required');
  }
  const key = `${req.ip}|${body.username.trim().toLowerCase()}`;
  const now = Date.now();
  let entry = failures.get(key);
  if (entry && now - entry.first > WINDOW_MS) entry = undefined;
  if (entry && entry.count >= MAX_FAILURES) {
    throw new v.HttpError(429, 'Too many failed login attempts. Try again later.');
  }

  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(body.username.trim());
  const ok = await verifyPassword(body.password, row ? row.password_hash : await dummyHash);
  if (!row || !ok) {
    failures.set(key, { first: entry ? entry.first : now, count: (entry ? entry.count : 0) + 1 });
    throw new v.HttpError(401, 'Invalid username or password');
  }
  failures.delete(key);
  res.json({ token: createSession(row.id), user: toUser(row) });
});

router.post('/logout', requireAuth, (req, res) => {
  destroySession(req.token);
  res.status(204).end();
});

router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

module.exports = router;
