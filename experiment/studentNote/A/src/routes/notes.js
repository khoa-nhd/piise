const express = require('express');
const db = require('../db');
const v = require('../validate');
const { requireAuth } = require('../auth');

const router = express.Router();
router.use(requireAuth);

function toNote(row) {
  return {
    id: row.id,
    userId: row.user_id,
    title: row.title,
    content: row.content,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// Notes are private: a note that belongs to someone else is reported as missing.
function findOwnNote(req) {
  const row = db.prepare('SELECT * FROM notes WHERE id = ? AND user_id = ?').get(v.id(req.params.id), req.user.id);
  if (!row) throw new v.HttpError(404, 'Note not found');
  return row;
}

router.get('/', (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  const rows = db
    .prepare(
      `SELECT * FROM notes
       WHERE user_id = ?
         AND (? = '' OR instr(lower(title), lower(?)) > 0 OR instr(lower(content), lower(?)) > 0)
       ORDER BY updated_at DESC, id DESC`
    )
    .all(req.user.id, q, q, q);
  res.json({ notes: rows.map(toNote) });
});

router.post('/', (req, res) => {
  const body = req.body ?? {};
  const { lastInsertRowid } = db
    .prepare('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)')
    .run(req.user.id, v.title(body.title), v.content(body.content));
  res.status(201).json({ note: toNote(db.prepare('SELECT * FROM notes WHERE id = ?').get(lastInsertRowid)) });
});

router.get('/:id', (req, res) => {
  res.json({ note: toNote(findOwnNote(req)) });
});

router.put('/:id', (req, res) => {
  const body = req.body ?? {};
  const note = findOwnNote(req);
  db.prepare('UPDATE notes SET title = ?, content = ?, updated_at = ? WHERE id = ?').run(
    v.title(body.title),
    v.content(body.content),
    new Date().toISOString(),
    note.id
  );
  res.json({ note: toNote(db.prepare('SELECT * FROM notes WHERE id = ?').get(note.id)) });
});

router.delete('/:id', (req, res) => {
  db.prepare('DELETE FROM notes WHERE id = ?').run(findOwnNote(req).id);
  res.status(204).end();
});

module.exports = router;
