export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export const ROLES = ['student', 'admin'];

// Validates a JSON body against an allow-list of fields. Unknown fields are
// rejected so clients cannot smuggle in values such as role or user_id.
export function readBody(req, spec) {
  if (!req.is('application/json')) {
    throw new HttpError(415, 'Content-Type must be application/json');
  }
  const body = req.body;
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new HttpError(400, 'Request body must be a JSON object');
  }
  for (const key of Object.keys(body)) {
    if (!Object.hasOwn(spec, key)) throw new HttpError(400, 'Unexpected field in request body');
  }
  const out = {};
  for (const [key, check] of Object.entries(spec)) out[key] = check(body[key]);
  return out;
}

export function parseId(value) {
  if (!/^[1-9]\d{0,14}$/.test(value)) throw new HttpError(400, 'Invalid id');
  return Number(value);
}

export function username(x) {
  if (typeof x !== 'string' || !/^[A-Za-z0-9_.-]{3,32}$/.test(x)) {
    throw new HttpError(400, 'username must be 3-32 characters (letters, digits, _ . -)');
  }
  return x;
}

export function newPassword(x) {
  if (typeof x !== 'string' || x.length < 10 || x.length > 128) {
    throw new HttpError(400, 'password must be 10-128 characters');
  }
  return x;
}

// Login only bounds the size; the policy is enforced when the password is set.
export function loginPassword(x) {
  if (typeof x !== 'string' || x.length < 1 || x.length > 128) {
    throw new HttpError(400, 'password is required');
  }
  return x;
}

export function title(x) {
  const t = typeof x === 'string' ? x.trim() : '';
  if (t.length < 1 || t.length > 200) throw new HttpError(400, 'title must be 1-200 characters');
  return t;
}

export function content(x) {
  if (typeof x !== 'string' || x.length > 10000) {
    throw new HttpError(400, 'content must be a string of at most 10000 characters');
  }
  return x;
}

export function role(x) {
  if (!ROLES.includes(x)) throw new HttpError(400, 'role must be student or admin');
  return x;
}
