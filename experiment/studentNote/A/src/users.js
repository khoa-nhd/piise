const db = require('./db');
const { hashPassword } = require('./auth');
const { HttpError } = require('./validate');

async function createUser({ username, password, fullName, role = 'student' }) {
  const passwordHash = await hashPassword(password);
  try {
    const { lastInsertRowid } = db
      .prepare('INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)')
      .run(username, passwordHash, fullName, role);
    return db.prepare('SELECT * FROM users WHERE id = ?').get(lastInsertRowid);
  } catch (err) {
    if (String(err.message).includes('UNIQUE')) throw new HttpError(409, 'Username is already taken');
    throw err;
  }
}

module.exports = { createUser };
