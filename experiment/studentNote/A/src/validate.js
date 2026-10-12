class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function string(value, field, { min = 0, max, pattern, trim = true } = {}) {
  if (typeof value !== 'string') throw new HttpError(400, `${field} is required`);
  const text = trim ? value.trim() : value;
  if (text.length < min) {
    throw new HttpError(400, min === 1 ? `${field} is required` : `${field} must be at least ${min} characters`);
  }
  if (text.length > max) throw new HttpError(400, `${field} must be at most ${max} characters`);
  if (pattern && !pattern.test(text)) throw new HttpError(400, `${field} contains invalid characters`);
  return text;
}

const username = (v) => string(v, 'username', { min: 3, max: 32, pattern: /^[A-Za-z0-9_.-]+$/ });
const password = (v) => string(v, 'password', { min: 8, max: 128, trim: false });
const fullName = (v) => string(v, 'fullName', { min: 1, max: 100 });
const title = (v) => string(v, 'title', { min: 1, max: 200 });
const content = (v) => string(v ?? '', 'content', { max: 20000, trim: false });

function role(value) {
  if (value !== 'student' && value !== 'admin') throw new HttpError(400, 'role must be "student" or "admin"');
  return value;
}

// Route ids are positive integers; anything else cannot match a row.
function id(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) throw new HttpError(404, 'Not found');
  return n;
}

module.exports = { HttpError, username, password, fullName, title, content, role, id };
