const express = require('express');

const MAX_TITLE = 200;
const MAX_CONTENT = 20000;

const SELECT_NOTE = `
  SELECT n.id, n.title, n.content, n.created_at, n.updated_at,
         n.user_id, u.username AS owner_username, u.full_name AS owner_name
    FROM notes n JOIN users u ON u.id = n.user_id`;

function parseNote(body) {
  const title = typeof body?.title === 'string' ? body.title.trim() : '';
  const content = body?.content ?? '';
  if (!title) return { error: 'Title is required' };
  if (title.length > MAX_TITLE) return { error: `Title must be at most ${MAX_TITLE} characters` };
  if (typeof content !== 'string') return { error: 'Content must be a string' };
  if (content.length > MAX_CONTENT) {
    return { error: `Content must be at most ${MAX_CONTENT} characters` };
  }
  return { title, content };
}

function notesRouter(db) {
  const router = express.Router();
  const getNote = db.prepare(`${SELECT_NOTE} WHERE n.id = ?`);

  // Students only ever reach their own notes; someone else's note looks like a missing one.
  router.param('id', (req, res, next, id) => {
    const note = /^\d+$/.test(id) ? getNote.get(Number(id)) : undefined;
    if (!note || (req.user.role !== 'admin' && note.user_id !== req.user.id)) {
      return res.status(404).json({ error: 'Note not found' });
    }
    req.note = note;
    next();
  });

  router.get('/', (req, res) => {
    const where = [];
    const params = [];
    if (req.user.role !== 'admin') {
      where.push('n.user_id = ?');
      params.push(req.user.id);
    } else if (req.query.userId !== undefined) {
      const userId = Number(req.query.userId);
      if (!Number.isInteger(userId)) return res.status(400).json({ error: 'Invalid userId' });
      where.push('n.user_id = ?');
      params.push(userId);
    }
    const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
    if (q) {
      const pattern = `%${q.replace(/[\\%_]/g, '\\$&')}%`;
      where.push("(n.title LIKE ? ESCAPE '\\' OR n.content LIKE ? ESCAPE '\\')");
      params.push(pattern, pattern);
    }
    const sql = `${SELECT_NOTE} ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
                 ORDER BY n.updated_at DESC, n.id DESC`;
    res.json({ notes: db.prepare(sql).all(...params) });
  });

  router.post('/', (req, res) => {
    const note = parseNote(req.body);
    if (note.error) return res.status(400).json({ error: note.error });
    const result = db
      .prepare('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)')
      .run(req.user.id, note.title, note.content);
    res.status(201).json({ note: getNote.get(Number(result.lastInsertRowid)) });
  });

  router.get('/:id', (req, res) => res.json({ note: req.note }));

  router.put('/:id', (req, res) => {
    const note = parseNote(req.body);
    if (note.error) return res.status(400).json({ error: note.error });
    db.prepare(
      `UPDATE notes SET title = ?, content = ?,
              updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        WHERE id = ?`
    ).run(note.title, note.content, req.note.id);
    res.json({ note: getNote.get(req.note.id) });
  });

  router.delete('/:id', (req, res) => {
    db.prepare('DELETE FROM notes WHERE id = ?').run(req.note.id);
    res.status(204).end();
  });

  return router;
}

module.exports = { notesRouter };
