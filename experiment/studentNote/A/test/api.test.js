process.env.DB_PATH = ':memory:';

const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../src/app');
const { createUser } = require('../src/users');

let server;
let base;

async function call(method, path, { token, body } = {}) {
  const res = await fetch(base + path, {
    method,
    headers: {
      ...(body !== undefined && { 'Content-Type': 'application/json' }),
      ...(token && { Authorization: `Bearer ${token}` }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, data: res.status === 204 ? null : await res.json() };
}

async function login(username, password) {
  const res = await call('POST', '/api/auth/login', { body: { username, password } });
  assert.equal(res.status, 200);
  return res.data.token;
}

test.before(async () => {
  await createUser({ username: 'admin', password: 'Admin@12345', fullName: 'Admin', role: 'admin' });
  await new Promise((resolve) => (server = app.listen(0, resolve)));
  base = `http://localhost:${server.address().port}`;
});

test.after(() => server.close());

test('register, login, me, logout', async () => {
  const reg = await call('POST', '/api/auth/register', {
    body: { username: 'alice', password: 'alicepass1', fullName: 'Alice', role: 'admin' },
  });
  assert.equal(reg.status, 201);
  assert.equal(reg.data.user.role, 'student', 'role in the register body is ignored');
  assert.equal(reg.data.user.passwordHash, undefined);

  assert.equal((await call('POST', '/api/auth/register', { body: { username: 'ALICE', password: 'alicepass1', fullName: 'A' } })).status, 409);
  assert.equal((await call('POST', '/api/auth/register', { body: { username: 'al', password: 'alicepass1', fullName: 'A' } })).status, 400);
  assert.equal((await call('POST', '/api/auth/register', { body: { username: 'carol', password: 'short', fullName: 'C' } })).status, 400);
  assert.equal((await call('POST', '/api/auth/login', { body: { username: 'alice', password: 'wrong-password' } })).status, 401);
  assert.equal((await call('POST', '/api/auth/login', { body: { username: 'nobody', password: 'wrong-password' } })).status, 401);

  const token = await login('alice', 'alicepass1');
  const me = await call('GET', '/api/auth/me', { token });
  assert.equal(me.data.user.username, 'alice');

  assert.equal((await call('POST', '/api/auth/logout', { token })).status, 204);
  assert.equal((await call('GET', '/api/auth/me', { token })).status, 401);
  assert.equal((await call('GET', '/api/notes')).status, 401);
});

test('notes CRUD is scoped to the owner', async () => {
  await call('POST', '/api/auth/register', { body: { username: 'bob', password: 'bobpass123', fullName: 'Bob' } });
  const alice = await login('alice', 'alicepass1');
  const bob = await login('bob', 'bobpass123');

  assert.equal((await call('POST', '/api/notes', { token: alice, body: { title: '  ', content: 'x' } })).status, 400);
  const created = await call('POST', '/api/notes', { token: alice, body: { title: 'Maths', content: 'Algebra 100%' } });
  assert.equal(created.status, 201);
  const id = created.data.note.id;
  await call('POST', '/api/notes', { token: alice, body: { title: 'History' } });

  assert.equal((await call('GET', '/api/notes', { token: alice })).data.notes.length, 2);
  assert.equal((await call('GET', '/api/notes?q=ALGEBRA', { token: alice })).data.notes.length, 1);
  assert.equal((await call('GET', '/api/notes?q=%25', { token: alice })).data.notes.length, 1, '% is matched literally');
  assert.equal((await call('GET', '/api/notes', { token: bob })).data.notes.length, 0);

  assert.equal((await call('GET', `/api/notes/${id}`, { token: bob })).status, 404);
  assert.equal((await call('PUT', `/api/notes/${id}`, { token: bob, body: { title: 'Hacked', content: '' } })).status, 404);
  assert.equal((await call('DELETE', `/api/notes/${id}`, { token: bob })).status, 404);
  assert.equal((await call('GET', '/api/notes/abc', { token: alice })).status, 404);

  const updated = await call('PUT', `/api/notes/${id}`, { token: alice, body: { title: 'Maths II', content: 'Calculus' } });
  assert.equal(updated.status, 200);
  assert.equal(updated.data.note.title, 'Maths II');
  assert.equal((await call('GET', `/api/notes/${id}`, { token: alice })).data.note.content, 'Calculus');

  assert.equal((await call('DELETE', `/api/notes/${id}`, { token: alice })).status, 204);
  assert.equal((await call('GET', `/api/notes/${id}`, { token: alice })).status, 404);
});

test('admin endpoints', async () => {
  const alice = await login('alice', 'alicepass1');
  const admin = await login('admin', 'Admin@12345');

  assert.equal((await call('GET', '/api/admin/users', { token: alice })).status, 403);
  assert.equal((await call('GET', '/api/admin/notes', { token: alice })).status, 403);

  const users = (await call('GET', '/api/admin/users', { token: admin })).data.users;
  const aliceRow = users.find((u) => u.username === 'alice');
  const adminRow = users.find((u) => u.username === 'admin');
  assert.equal(aliceRow.noteCount, 1);

  const stats = (await call('GET', '/api/admin/stats', { token: admin })).data;
  assert.deepEqual(stats, { users: 3, admins: 1, students: 2, notes: 1 });

  const allNotes = (await call('GET', '/api/admin/notes', { token: admin })).data.notes;
  assert.equal(allNotes.length, 1);
  assert.equal(allNotes[0].owner.username, 'alice');
  assert.equal((await call('GET', `/api/admin/notes?userId=${adminRow.id}`, { token: admin })).data.notes.length, 0);

  const created = await call('POST', '/api/admin/users', {
    token: admin,
    body: { username: 'dave', password: 'davepass12', fullName: 'Dave', role: 'student' },
  });
  assert.equal(created.status, 201);
  const daveId = created.data.user.id;
  const dave = await login('dave', 'davepass12');

  // Password reset signs the user out everywhere and the new password works.
  const reset = await call('PUT', `/api/admin/users/${daveId}`, { token: admin, body: { password: 'newpass1234', role: 'admin' } });
  assert.equal(reset.data.user.role, 'admin');
  assert.equal((await call('GET', '/api/auth/me', { token: dave })).status, 401);
  await login('dave', 'newpass1234');

  assert.equal((await call('PUT', `/api/admin/users/${adminRow.id}`, { token: admin, body: { role: 'student' } })).status, 400);
  assert.equal((await call('DELETE', `/api/admin/users/${adminRow.id}`, { token: admin })).status, 400);
  assert.equal((await call('PUT', `/api/admin/users/${daveId}`, { token: admin, body: { role: 'root' } })).status, 400);

  assert.equal((await call('DELETE', `/api/admin/notes/${allNotes[0].id}`, { token: admin })).status, 204);
  assert.equal((await call('DELETE', `/api/admin/notes/${allNotes[0].id}`, { token: admin })).status, 404);

  // Deleting a user removes their notes and sessions.
  await call('POST', '/api/notes', { token: alice, body: { title: 'Temp' } });
  assert.equal((await call('DELETE', `/api/admin/users/${aliceRow.id}`, { token: admin })).status, 204);
  assert.equal((await call('GET', '/api/auth/me', { token: alice })).status, 401);
  assert.equal((await call('GET', '/api/admin/notes', { token: admin })).data.notes.length, 0);
});

test('unknown api routes and malformed JSON return JSON errors', async () => {
  assert.equal((await call('GET', '/api/nope')).status, 404);
  const res = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{bad' });
  assert.equal(res.status, 400);
  assert.ok((await res.json()).error);
});
