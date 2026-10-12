const express = require('express');
const db = require('../db');
const v = require('../validate');
const { createUser } = require('../users');
const { hashPassword, destroyUserSessions, toUser, requireAuth, requireAdmin } = require('../auth');

const router = express.Router();
router.use(requireAuth, requireAdmin);

function findUser(req) {
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(v.id(req.params.id));
  if (!row) throw new v.HttpError(404, 'User not found');
  return row;
}

router.get('/stats', (req, res) => {
  const users = db
    .prepare(`SELECT COUNT(*) AS total, COALESCE(SUM(role = 'admin'), 0) AS admins FROM users`)
    .get();
  const { total: notes } = db.prepare('SELECT COUNT(*) AS total FROM notes').get();
  res.json({ users: users.total, admins: users.admins, students: users.total - users.admins, notes });
});

router.get('/users', (req, res) => {
  const rows = db
    .prepare(
      `SELECT u.*, (SELECT COUNT(*) FROM notes n WHERE n.user_id = u.id) AS note_count
       FROM users u ORDER BY u.id`
    )
    .all();
  res.json({ users: rows.map((row) => ({ ...toUser(row), noteCount: row.note_count })) });
});

router.post('/users', async (req, res) => {
  const body = req.body ?? {};
  const user = await createUser({
    username: v.username(body.username),
    password: v.password(body.password),
    fullName: v.fullName(body.fullName),
    role: v.role(body.role ?? 'student'),
  });
  res.status(201).json({ user: toUser(user) });
});

router.put('/users/:id', async (req, res) => {
  const body = req.body ?? {};
  const user = findUser(req);
  const fullName = body.fullName === undefined ? user.full_name : v.fullName(body.fullName);
  const role = body.role === undefined ? user.role : v.role(body.role);
  // Keeps at least one admin: the acting admin can never demote themselves.
  if (user.id === req.user.id && role !== 'admin') {
    throw new v.HttpError(400, 'You cannot remove your own admin role');
  }
  let passwordHash = user.password_hash;
  if (body.password !== undefined) {
    passwordHash = await hashPassword(v.password(body.password));
    destroyUserSessions(user.id);
  }
  db.prepare('UPDATE users SET full_name = ?, role = ?, password_hash = ? WHERE id = ?').run(
    fullName,
    role,
    passwordHash,
    user.id
  );
  res.json({ user: toUser(db.prepare('SELECT * FROM users WHERE id = ?').get(user.id)) });
});

router.delete('/users/:id', (req, res) => {
  const user = findUser(req);
  if (user.id === req.user.id) throw new v.HttpError(400, 'You cannot delete your own account');
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
  res.status(204).end();
});

router.get('/notes', (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  const userId = req.query.userId === undefined ? 0 : v.id(req.query.userId);
  const rows = db
    .prepare(
      `SELECT n.*, u.username, u.full_name
       FROM notes n JOIN users u ON u.id = n.user_id
       WHERE (? = 0 OR n.user_id = ?)
         AND (? = '' OR instr(lower(n.title), lower(?)) > 0 OR instr(lower(n.content), lower(?)) > 0)
       ORDER BY n.updated_at DESC, n.id DESC`
    )
    .all(userId, userId, q, q, q);
  res.json({
    notes: rows.map((row) => ({
      id: row.id,
      userId: row.user_id,
      title: row.title,
      content: row.content,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      owner: { id: row.user_id, username: row.username, fullName: row.full_name },
    })),
  });
});

router.delete('/notes/:id', (req, res) => {
  const { changes } = db.prepare('DELETE FROM notes WHERE id = ?').run(v.id(req.params.id));
  if (!changes) throw new v.HttpError(404, 'Note not found');
  res.status(204).end();
});

module.exports = router;
