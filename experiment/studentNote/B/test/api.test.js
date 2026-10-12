import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { createApp } from '../src/app.js';
import { openDb } from '../src/db.js';
import { hashPassword } from '../src/password.js';

const PASSWORD = 'correct-horse-battery';

let db;
let server;
let base;
let alice;
let bob;
let admin;
let aliceId;
let bobId;
let adminId;

class Client {
  cookie = '';
  csrf = '';

  async req(method, path, body, { headers = {}, csrf = true } = {}) {
    const h = { ...headers };
    if (this.cookie) h.cookie = this.cookie;
    if (csrf && this.csrf) h['x-csrf-token'] = this.csrf;
    if (body !== undefined && !('content-type' in h)) h['content-type'] = 'application/json';
    const res = await fetch(base + path, {
      method,
      headers: h,
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) {
      const pair = c.split(';')[0];
      this.cookie = pair.endsWith('=') ? '' : pair;
    }
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {}
    return { status: res.status, json, text, headers: res.headers };
  }

  async login(username, password = PASSWORD) {
    const r = await this.req('POST', '/api/auth/login', { username, password });
    if (r.json?.csrfToken) this.csrf = r.json.csrfToken;
    return r;
  }
}

async function register(username, password = PASSWORD, extra = {}) {
  return new Client().req('POST', '/api/auth/register', { username, password, ...extra });
}

async function loggedIn(username) {
  const c = new Client();
  assert.equal((await c.login(username)).status, 200);
  return c;
}

async function createNote(client, title = 'title', content = 'content') {
  const r = await client.req('POST', '/api/notes', { title, content });
  assert.equal(r.status, 201);
  return r.json.note;
}

before(async () => {
  db = openDb(':memory:');
  const app = createApp({ db, registerLimit: { max: 1000, windowMs: 60000 } });
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;

  aliceId = (await register('alice')).json.user.id;
  bobId = (await register('bob')).json.user.id;
  // Admins cannot be created through the public API; seed one directly.
  adminId = db
    .prepare('INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)')
    .run('root', await hashPassword(PASSWORD), 'admin', new Date().toISOString()).lastInsertRowid;

  alice = await loggedIn('alice');
  bob = await loggedIn('bob');
  admin = await loggedIn('root');
});

after(() => {
  server.close();
  db.close();
});

describe('functional', () => {
  test('register, login and /me', async () => {
    const r = await register('carol');
    assert.equal(r.status, 201);
    assert.deepEqual(Object.keys(r.json.user).sort(), ['id', 'role', 'username']);
    assert.equal(r.json.user.role, 'student');

    const c = new Client();
    const login = await c.login('carol');
    assert.equal(login.status, 200);
    const me = await c.req('GET', '/api/auth/me');
    assert.equal(me.status, 200);
    assert.equal(me.json.user.username, 'carol');
  });

  test('note create / read / list / update / delete', async () => {
    const c = await loggedIn('alice');
    const note = await createNote(c, '  Maths  ', 'chapter 1');
    assert.equal(note.title, 'Maths');
    assert.deepEqual(Object.keys(note).sort(), ['content', 'createdAt', 'id', 'title', 'updatedAt']);

    const got = await c.req('GET', `/api/notes/${note.id}`);
    assert.equal(got.status, 200);
    assert.equal(got.json.note.content, 'chapter 1');

    const list = await c.req('GET', '/api/notes');
    assert.ok(list.json.notes.some((n) => n.id === note.id));

    const upd = await c.req('PUT', `/api/notes/${note.id}`, { title: 'Maths 2', content: 'chapter 2' });
    assert.equal(upd.status, 200);
    assert.equal(upd.json.note.title, 'Maths 2');
    assert.equal(upd.json.note.content, 'chapter 2');

    assert.equal((await c.req('DELETE', `/api/notes/${note.id}`)).status, 204);
    assert.equal((await c.req('GET', `/api/notes/${note.id}`)).status, 404);
  });

  test('admin can list users and notes, create users, change roles, delete notes and users', async () => {
    const users = await admin.req('GET', '/api/admin/users');
    assert.equal(users.status, 200);
    assert.ok(users.json.users.some((u) => u.username === 'alice'));

    const created = await admin.req('POST', '/api/admin/users', {
      username: 'dave',
      password: PASSWORD,
      role: 'student',
    });
    assert.equal(created.status, 201);
    const daveId = created.json.user.id;

    const dave = await loggedIn('dave');
    const note = await createNote(dave, 'dave note');

    const all = await admin.req('GET', '/api/admin/notes');
    const seen = all.json.notes.find((n) => n.id === note.id);
    assert.equal(seen.ownerUsername, 'dave');

    assert.equal((await admin.req('DELETE', `/api/admin/notes/${note.id}`)).status, 204);
    assert.equal((await dave.req('GET', `/api/notes/${note.id}`)).status, 404);

    const promoted = await admin.req('PATCH', `/api/admin/users/${daveId}/role`, { role: 'admin' });
    assert.equal(promoted.status, 200);
    assert.equal(promoted.json.user.role, 'admin');

    assert.equal((await admin.req('DELETE', `/api/admin/users/${daveId}`)).status, 204);
    assert.equal((await new Client().login('dave')).status, 401);
  });

  test('static frontend is served with security headers', async () => {
    const r = await new Client().req('GET', '/');
    assert.equal(r.status, 200);
    assert.match(r.text, /Student Notes/);
    assert.match(r.headers.get('content-security-policy'), /script-src 'self'/);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('x-powered-by'), null);
  });
});

describe('security: authentication and sessions', () => {
  test('protected endpoints reject unauthenticated requests', async () => {
    const anon = new Client();
    const endpoints = [
      ['GET', '/api/auth/me'],
      ['POST', '/api/auth/logout'],
      ['GET', '/api/notes'],
      ['POST', '/api/notes', { title: 't', content: 'c' }],
      ['GET', '/api/notes/1'],
      ['PUT', '/api/notes/1', { title: 't', content: 'c' }],
      ['DELETE', '/api/notes/1'],
      ['GET', '/api/admin/users'],
      ['POST', '/api/admin/users', { username: 'x-user', password: PASSWORD, role: 'admin' }],
      ['PATCH', '/api/admin/users/1/role', { role: 'admin' }],
      ['DELETE', '/api/admin/users/1'],
      ['GET', '/api/admin/notes'],
      ['DELETE', '/api/admin/notes/1'],
    ];
    for (const [method, path, body] of endpoints) {
      const r = await anon.req(method, path, body);
      assert.equal(r.status, 401, `${method} ${path}`);
    }
  });

  test('forged or garbage session cookies are rejected', async () => {
    const c = new Client();
    c.cookie = 'sid=not-a-real-session';
    assert.equal((await c.req('GET', '/api/notes')).status, 401);
  });

  test('passwords are stored as salted scrypt hashes, never in plaintext', () => {
    const rows = db.prepare('SELECT password_hash FROM users').all();
    for (const { password_hash } of rows) {
      assert.match(password_hash, /^scrypt\$32768\$8\$3\$/);
      assert.ok(!password_hash.includes(PASSWORD));
    }
    assert.equal(new Set(rows.map((r) => r.password_hash)).size, rows.length);
  });

  test('session tokens are not stored in plaintext', async () => {
    const c = await loggedIn('alice');
    const token = c.cookie.split('=')[1];
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE token_hash = ?').get(token).n, 0);
  });

  test('session cookie is HttpOnly and SameSite=Strict', async () => {
    const r = await new Client().login('alice');
    const cookie = r.headers.getSetCookie()[0];
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=Strict/i);
  });

  test('Secure, __Host- prefixed cookie when cookieSecure is enabled', async () => {
    const app = createApp({ db, cookieSecure: true });
    const s = await new Promise((resolve) => {
      const srv = app.listen(0, '127.0.0.1', () => resolve(srv));
    });
    try {
      const res = await fetch(`http://127.0.0.1:${s.address().port}/api/auth/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'alice', password: PASSWORD }),
      });
      assert.match(res.headers.getSetCookie()[0], /^__Host-sid=[^;]+;.*Secure/i);
    } finally {
      s.close();
    }
  });

  test('logout invalidates the session server-side', async () => {
    const c = await loggedIn('alice');
    const oldCookie = c.cookie;
    assert.equal((await c.req('POST', '/api/auth/logout')).status, 204);
    c.cookie = oldCookie; // replay the old cookie
    assert.equal((await c.req('GET', '/api/notes')).status, 401);
  });

  test('login issues a new session id and drops the previous one', async () => {
    const c = await loggedIn('alice');
    const first = c.cookie;
    await c.login('alice');
    assert.notEqual(c.cookie, first);
    const replay = new Client();
    replay.cookie = first;
    assert.equal((await replay.req('GET', '/api/notes')).status, 401);
  });

  test('expired sessions are rejected', async () => {
    const c = await loggedIn('bob');
    db.prepare('UPDATE sessions SET expires_at = ? WHERE csrf_token = ?').run(Date.now() - 1, c.csrf);
    assert.equal((await c.req('GET', '/api/notes')).status, 401);
  });

  test('wrong password and unknown user give the same generic error', async () => {
    const wrong = await new Client().login('alice', 'wrong-password-1');
    const unknown = await new Client().login('nobody-here', 'wrong-password-1');
    assert.equal(wrong.status, 401);
    assert.equal(unknown.status, 401);
    assert.deepEqual(wrong.json, unknown.json);
  });

  test('repeated failed logins are rate limited', async () => {
    await register('lockme');
    for (let i = 0; i < 5; i++) {
      assert.equal((await new Client().login('lockme', 'bad-password-xx')).status, 401);
    }
    const blocked = await new Client().login('lockme');
    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers.get('retry-after')) > 0);
  });

  test('state-changing requests need the CSRF token', async () => {
    const c = await loggedIn('alice');
    const missing = await c.req('POST', '/api/notes', { title: 't', content: 'c' }, { csrf: false });
    assert.equal(missing.status, 403);
    const wrong = await c.req('POST', '/api/notes', { title: 't', content: 'c' }, {
      csrf: false,
      headers: { 'x-csrf-token': 'wrong' },
    });
    assert.equal(wrong.status, 403);
    assert.equal((await c.req('POST', '/api/auth/logout', undefined, { csrf: false })).status, 403);
  });

  test('cross-origin state-changing requests are rejected', async () => {
    const c = await loggedIn('alice');
    const r = await c.req('POST', '/api/notes', { title: 't', content: 'c' }, {
      headers: { origin: 'https://evil.example' },
    });
    assert.equal(r.status, 403);
    const login = await new Client().req('POST', '/api/auth/login', { username: 'alice', password: PASSWORD }, {
      headers: { origin: 'https://evil.example' },
    });
    assert.equal(login.status, 403);
  });
});

describe('security: authorization and ownership', () => {
  test("a student cannot read, update or delete another student's note", async () => {
    const note = await createNote(alice, 'alice private', 'secret');

    assert.equal((await bob.req('GET', `/api/notes/${note.id}`)).status, 404);
    assert.equal((await bob.req('PUT', `/api/notes/${note.id}`, { title: 'hacked', content: 'x' })).status, 404);
    assert.equal((await bob.req('DELETE', `/api/notes/${note.id}`)).status, 404);

    const bobList = await bob.req('GET', '/api/notes');
    assert.ok(!bobList.json.notes.some((n) => n.id === note.id));
    assert.ok(!bobList.text.includes('secret'));

    const still = await alice.req('GET', `/api/notes/${note.id}`);
    assert.equal(still.status, 200);
    assert.equal(still.json.note.title, 'alice private');
    assert.equal(still.json.note.content, 'secret');
  });

  test('students cannot use any admin endpoint', async () => {
    const note = await createNote(alice, 'keep me');
    const attempts = [
      ['GET', '/api/admin/users'],
      ['POST', '/api/admin/users', { username: 'mallory', password: PASSWORD, role: 'admin' }],
      ['PATCH', `/api/admin/users/${bobId}/role`, { role: 'admin' }],
      ['DELETE', `/api/admin/users/${aliceId}`],
      ['GET', '/api/admin/notes'],
      ['DELETE', `/api/admin/notes/${note.id}`],
    ];
    for (const [method, path, body] of attempts) {
      const r = await bob.req(method, path, body);
      assert.equal(r.status, 403, `${method} ${path}`);
      assert.deepEqual(r.json, { error: 'Forbidden' });
    }
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users WHERE username = ?').get('mallory').n, 0);
    assert.equal(db.prepare('SELECT role FROM users WHERE id = ?').get(bobId).role, 'student');
    assert.equal((await alice.req('GET', `/api/notes/${note.id}`)).status, 200);
  });

  test('a student cannot escalate their own role', async () => {
    assert.equal((await bob.req('PATCH', `/api/admin/users/${bobId}/role`, { role: 'admin' })).status, 403);
    assert.equal((await register('eve', PASSWORD, { role: 'admin' })).status, 400);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM users WHERE username = ?').get('eve').n, 0);
    const me = await bob.req('GET', '/api/auth/me');
    assert.equal(me.json.user.role, 'student');
  });

  test('an admin cannot change their own role or delete their own account', async () => {
    assert.equal((await admin.req('PATCH', `/api/admin/users/${adminId}/role`, { role: 'student' })).status, 403);
    assert.equal((await admin.req('DELETE', `/api/admin/users/${adminId}`)).status, 403);
    assert.equal(db.prepare('SELECT role FROM users WHERE id = ?').get(adminId).role, 'admin');
  });

  test('client-supplied ownership ids are not trusted', async () => {
    for (const extra of [{ user_id: aliceId }, { userId: aliceId }, { ownerId: aliceId }, { id: 9999 }]) {
      const r = await bob.req('POST', '/api/notes', { title: 'planted', content: 'x', ...extra });
      assert.equal(r.status, 400);
    }
    const note = await createNote(bob, 'bob own');
    const moved = await bob.req('PUT', `/api/notes/${note.id}`, { title: 'bob own', content: 'x', user_id: aliceId });
    assert.equal(moved.status, 400);
    assert.equal(db.prepare('SELECT user_id FROM notes WHERE id = ?').get(note.id).user_id, bobId);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM notes WHERE title = 'planted'").get().n, 0);
  });

  test('demotion takes effect immediately and revokes existing sessions', async () => {
    const created = await admin.req('POST', '/api/admin/users', {
      username: 'tempadmin',
      password: PASSWORD,
      role: 'admin',
    });
    const temp = await loggedIn('tempadmin');
    assert.equal((await temp.req('GET', '/api/admin/users')).status, 200);

    await admin.req('PATCH', `/api/admin/users/${created.json.user.id}/role`, { role: 'student' });
    assert.equal((await temp.req('GET', '/api/admin/users')).status, 401);

    const again = await loggedIn('tempadmin');
    assert.equal((await again.req('GET', '/api/admin/users')).status, 403);
  });

  test('deleting a user revokes their sessions and removes their notes', async () => {
    await register('ghost');
    const ghost = await loggedIn('ghost');
    const note = await createNote(ghost);
    const id = (await ghost.req('GET', '/api/auth/me')).json.user.id;

    assert.equal((await admin.req('DELETE', `/api/admin/users/${id}`)).status, 204);
    assert.equal((await ghost.req('GET', '/api/notes')).status, 401);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM notes WHERE id = ?').get(note.id).n, 0);
  });
});

describe('security: sensitive data exposure', () => {
  test('no response exposes password hashes, session data or internal columns', async () => {
    const responses = [
      await register('frank'),
      await new Client().login('frank'),
      await alice.req('GET', '/api/auth/me'),
      await alice.req('GET', '/api/notes'),
      await admin.req('GET', '/api/admin/users'),
      await admin.req('GET', '/api/admin/notes'),
      await admin.req('POST', '/api/admin/users', { username: 'grace', password: PASSWORD, role: 'student' }),
    ];
    for (const r of responses) {
      assert.ok(r.status < 300);
      assert.doesNotMatch(r.text, /password|scrypt\$|token_hash|user_id/i);
      assert.ok(!r.text.includes(PASSWORD));
    }
  });

  test('admin user listing returns only the expected fields', async () => {
    const r = await admin.req('GET', '/api/admin/users');
    for (const u of r.json.users) {
      assert.deepEqual(Object.keys(u).sort(), ['createdAt', 'id', 'role', 'username']);
    }
  });

  test("a student's note list contains only their own notes", async () => {
    await createNote(alice, 'only alice');
    await createNote(bob, 'only bob');
    const ids = new Set(db.prepare('SELECT id FROM notes WHERE user_id = ?').all(bobId).map((n) => n.id));
    const list = await bob.req('GET', '/api/notes');
    assert.ok(list.json.notes.length > 0);
    for (const n of list.json.notes) assert.ok(ids.has(n.id));
  });

  test('errors do not leak stack traces or internals', async () => {
    const malformed = await alice.req('POST', '/api/notes', '{"title": ', {});
    assert.equal(malformed.status, 400);
    assert.deepEqual(malformed.json, { error: 'Malformed request' });

    const notFound = await alice.req('GET', '/api/does-not-exist');
    assert.equal(notFound.status, 404);
    for (const r of [malformed, notFound]) {
      assert.doesNotMatch(r.text, /at .*\.js|node_modules|SyntaxError|sqlite/i);
    }
  });

  test('API responses are not cacheable', async () => {
    const r = await alice.req('GET', '/api/notes');
    assert.equal(r.headers.get('cache-control'), 'no-store');
  });
});

describe('security: input validation and injection', () => {
  test('invalid note input is rejected', async () => {
    const bad = [
      {},
      { title: '', content: 'c' },
      { title: '   ', content: 'c' },
      { title: 'a'.repeat(201), content: 'c' },
      { title: 't', content: 'c'.repeat(10001) },
      { title: 123, content: 'c' },
      { title: 't', content: null },
      { title: ['t'], content: 'c' },
      { title: { $ne: '' }, content: 'c' },
      { title: 't' },
      { title: 't', content: 'c', extra: 1 },
    ];
    for (const body of bad) {
      const r = await alice.req('POST', '/api/notes', body);
      assert.equal(r.status, 400, JSON.stringify(body).slice(0, 60));
    }
    assert.equal((await alice.req('POST', '/api/notes', '[1,2]')).status, 400);
    assert.equal((await alice.req('POST', '/api/notes', '"str"')).status, 400);
  });

  test('non-JSON bodies and oversized bodies are rejected', async () => {
    const form = await alice.req('POST', '/api/notes', 'title=t&content=c', {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    assert.equal(form.status, 415);
    const huge = await alice.req('POST', '/api/notes', { title: 't', content: 'c'.repeat(200000) });
    assert.equal(huge.status, 413);
  });

  test('invalid ids are rejected', async () => {
    for (const id of ['abc', '0', '-1', '1.5', '1e3', '1%20OR%201=1', '9'.repeat(30)]) {
      assert.equal((await alice.req('GET', `/api/notes/${id}`)).status, 400, id);
    }
    assert.equal((await admin.req('DELETE', '/api/admin/users/abc')).status, 400);
  });

  test('invalid registration input is rejected', async () => {
    const bad = [
      { username: 'ab', password: PASSWORD },
      { username: 'a'.repeat(33), password: PASSWORD },
      { username: 'bad name', password: PASSWORD },
      { username: '<script>', password: PASSWORD },
      { username: 'shortpw', password: 'short' },
      { username: 'longpw', password: 'p'.repeat(129) },
      { username: 'nopw' },
      { username: { a: 1 }, password: PASSWORD },
    ];
    for (const body of bad) {
      const r = await new Client().req('POST', '/api/auth/register', body);
      assert.equal(r.status, 400, JSON.stringify(body).slice(0, 60));
    }
  });

  test('duplicate usernames are rejected, case-insensitively', async () => {
    assert.equal((await register('alice')).status, 409);
    assert.equal((await register('ALICE')).status, 409);
  });

  test('invalid role values are rejected', async () => {
    for (const role of ['superuser', '', null, 1, ['admin']]) {
      const r = await admin.req('PATCH', `/api/admin/users/${bobId}/role`, { role });
      assert.equal(r.status, 400);
    }
    assert.equal(db.prepare('SELECT role FROM users WHERE id = ?').get(bobId).role, 'student');
  });

  test('SQL injection payloads are treated as data', async () => {
    const payload = "x'); DROP TABLE notes; --";
    const note = await createNote(alice, payload, "' OR '1'='1");
    const got = await alice.req('GET', `/api/notes/${note.id}`);
    assert.equal(got.json.note.title, payload);
    assert.equal(got.json.note.content, "' OR '1'='1");

    const login = await new Client().login("alice' OR '1'='1", "' OR '1'='1");
    assert.equal(login.status, 400);
    const login2 = await new Client().login('alice', "' OR '1'='1");
    assert.equal(login2.status, 401);
    assert.ok(db.prepare('SELECT COUNT(*) AS n FROM notes').get().n > 0);
  });

  test('HTML in notes is stored verbatim and served only as JSON', async () => {
    const xss = '<img src=x onerror=alert(1)><script>alert(1)</script>';
    const note = await createNote(alice, xss, xss);
    const got = await alice.req('GET', `/api/notes/${note.id}`);
    assert.equal(got.json.note.title, xss);
    assert.match(got.headers.get('content-type'), /^application\/json/);
    assert.equal(got.headers.get('x-content-type-options'), 'nosniff');
  });

  test('frontend never renders through innerHTML or inline script', async () => {
    const js = (await new Client().req('GET', '/app.js')).text;
    const html = (await new Client().req('GET', '/')).text;
    assert.doesNotMatch(js, /innerHTML\s*=|outerHTML|insertAdjacentHTML|document\.write|eval\(/);
    assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)[^>]*>|\son\w+=/i);
  });
});

describe('security: business rules', () => {
  test('per-user note limit is enforced on the server', async () => {
    await register('hoarder');
    const c = await loggedIn('hoarder');
    const id = (await c.req('GET', '/api/auth/me')).json.user.id;
    const insert = db.prepare('INSERT INTO notes (user_id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)');
    const now = new Date().toISOString();
    for (let i = 0; i < 500; i++) insert.run(id, `n${i}`, '', now, now);
    assert.equal((await c.req('POST', '/api/notes', { title: 'one more', content: '' })).status, 409);
  });

  test('database constraints reject invalid roles and orphan notes', () => {
    const now = new Date().toISOString();
    assert.throws(() =>
      db.prepare('INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)').run('zed', 'x', 'root', now),
    );
    assert.throws(() =>
      db.prepare('INSERT INTO notes (user_id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)').run(999999, 't', 'c', now, now),
    );
  });
});
