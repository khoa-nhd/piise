const crypto = require('node:crypto');
const { promisify } = require('node:util');
const db = require('./db');
const { HttpError } = require('./validate');

const scrypt = promisify(crypto.scrypt);
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

async function verifyPassword(password, stored) {
  const [, saltHex, hashHex] = stored.split('$');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = await scrypt(password, Buffer.from(saltHex, 'hex'), expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(new Date().toISOString());
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(sha256(token), userId, expiresAt);
  return token;
}

function destroySession(token) {
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
}

function destroyUserSessions(userId) {
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
}

function toUser(row) {
  return { id: row.id, username: row.username, fullName: row.full_name, role: row.role, createdAt: row.created_at };
}

function requireAuth(req, res, next) {
  const match = /^Bearer (\S+)$/.exec(req.get('authorization') || '');
  if (!match) throw new HttpError(401, 'Authentication required');
  const row = db
    .prepare(
      `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > ?`
    )
    .get(sha256(match[1]), new Date().toISOString());
  if (!row) throw new HttpError(401, 'Session expired or invalid');
  req.user = toUser(row);
  req.token = match[1];
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') throw new HttpError(403, 'Admin access required');
  next();
}

module.exports = {
  hashPassword,
  verifyPassword,
  createSession,
  destroySession,
  destroyUserSessions,
  toUser,
  requireAuth,
  requireAdmin,
};
