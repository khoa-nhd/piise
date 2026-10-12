const express = require('express');
const { hashPassword } = require('./passwords');

const ROLES = ['student', 'admin'];
const USERNAME_RE = /^[a-zA-Z0-9_.]{3,32}$/;
const MIN_PASSWORD = 8;
const MAX_PASSWORD = 128;
const MAX_NAME = 100;

const SELECT_USER = `
  SELECT u.id, u.username, u.full_name, u.role, u.created_at,
         (SELECT COUNT(*) FROM notes n WHERE n.user_id = u.id) AS note_count
    FROM users u`;

function checkPassword(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD) {
    return `Password must be at least ${MIN_PASSWORD} characters`;
  }
  if (password.length > MAX_PASSWORD) return `Password must be at most ${MAX_PASSWORD} characters`;
  return null;
}

function checkProfile({ full_name, role }) {
  if (typeof full_name !== 'string' || !full_name.trim()) return 'Full name is required';
  if (full_name.trim().length > MAX_NAME) return `Full name must be at most ${MAX_NAME} characters`;
  if (!ROLES.includes(role)) return 'Role must be "student" or "admin"';
  return null;
}

function usersRouter(db) {
  const router = express.Router();
  const getUser = db.prepare(`${SELECT_USER} WHERE u.id = ?`);

  router.param('id', (req, res, next, id) => {
    const user = /^\d+$/.test(id) ? getUser.get(Number(id)) : undefined;
    if (!user) return res.status(404).json({ error: 'User not found' });
    req.target = user;
    next();
  });

  router.get('/', (req, res) => {
    res.json({ users: db.prepare(`${SELECT_USER} ORDER BY u.role, u.username`).all() });
  });

  router.post('/', (req, res) => {
    const body = req.body ?? {};
    const role = body.role ?? 'student';
    if (typeof body.username !== 'string' || !USERNAME_RE.test(body.username)) {
      return res
        .status(400)
        .json({ error: 'Username must be 3-32 characters: letters, digits, "_" or "."' });
    }
    const error = checkProfile({ full_name: body.full_name, role }) || checkPassword(body.password);
    if (error) return res.status(400).json({ error });
    if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(body.username)) {
      return res.status(409).json({ error: 'Username is already taken' });
    }
    const result = db
      .prepare('INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)')
      .run(body.username, hashPassword(body.password), body.full_name.trim(), role);
    res.status(201).json({ user: getUser.get(Number(result.lastInsertRowid)) });
  });

  router.put('/:id', (req, res) => {
    const body = req.body ?? {};
    const full_name = body.full_name ?? req.target.full_name;
    const role = body.role ?? req.target.role;
    const hasPassword = body.password !== undefined && body.password !== '';
    const error = checkProfile({ full_name, role }) || (hasPassword && checkPassword(body.password));
    if (error) return res.status(400).json({ error });
    if (req.target.id === req.user.id && role !== 'admin') {
      return res.status(400).json({ error: 'You cannot remove your own admin role' });
    }
    db.prepare('UPDATE users SET full_name = ?, role = ? WHERE id = ?').run(
      full_name.trim(),
      role,
      req.target.id
    );
    if (hasPassword) {
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(
        hashPassword(body.password),
        req.target.id
      );
      // A reset password signs the user out everywhere.
      db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.target.id);
    }
    res.json({ user: getUser.get(req.target.id) });
  });

  router.delete('/:id', (req, res) => {
    if (req.target.id === req.user.id) {
      return res.status(400).json({ error: 'You cannot delete your own account' });
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(req.target.id);
    res.status(204).end();
  });

  return router;
}

module.exports = { usersRouter };
