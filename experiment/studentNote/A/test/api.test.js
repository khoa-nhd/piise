const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { openDb } = require('../src/db');
const { createApp } = require('../src/app');

let server;
let base;

before(async () => {
  server = createApp(openDb(':memory:')).listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

// Minimal client that keeps the session cookie between requests.
function client() {
  let cookie = '';
  return async (method, path, body) => {
    const res = await fetch(base + path, {
      method,
      headers: { ...(body && { 'Content-Type': 'application/json' }), ...(cookie && { cookie }) },
      body: body && JSON.stringify(body),
    });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };
}

async function loginAs(username, password) {
  const request = client();
  const res = await request('POST', '/api/auth/login', { username, password });
  assert.equal(res.status, 200);
  return request;
}

test('rejects unauthenticated requests and bad credentials', async () => {
  const anon = client();
  assert.equal((await anon('GET', '/api/notes')).status, 401);
  assert.equal((await anon('GET', '/api/auth/me')).status, 401);
  const bad = await anon('POST', '/api/auth/login', { username: 'student1', password: 'wrong' });
  assert.equal(bad.status, 401);
  assert.equal((await anon('POST', '/api/auth/login', {})).status, 400);
});

test('student can create, read, update, search and delete their notes', async () => {
  const student = await loginAs('student1', 'Student@123');
  assert.equal((await student('GET', '/api/auth/me')).body.user.role, 'student');

  const created = await student('POST', '/api/notes', { title: ' Algebra ', content: '100% done' });
  assert.equal(created.status, 201);
  assert.equal(created.body.note.title, 'Algebra');
  const id = created.body.note.id;

  assert.equal((await student('GET', `/api/notes/${id}`)).body.note.content, '100% done');

  const updated = await student('PUT', `/api/notes/${id}`, { title: 'Algebra II', content: 'x' });
  assert.equal(updated.body.note.title, 'Algebra II');

  assert.equal((await student('GET', '/api/notes')).body.notes.length, 2);
  assert.equal((await student('GET', '/api/notes?q=algebra')).body.notes.length, 1);
  assert.equal((await student('GET', '/api/notes?q=%25')).body.notes.length, 0);

  assert.equal((await student('POST', '/api/notes', { title: '   ' })).status, 400);
  assert.equal((await student('PUT', `/api/notes/${id}`, { content: 'no title' })).status, 400);

  assert.equal((await student('DELETE', `/api/notes/${id}`)).status, 204);
  assert.equal((await student('GET', `/api/notes/${id}`)).status, 404);
});

test('students cannot reach other users notes or admin endpoints', async () => {
  const admin = await loginAs('admin', 'Admin@123');
  const student = await loginAs('student1', 'Student@123');

  const adminNote = (await admin('POST', '/api/notes', { title: 'Private' })).body.note;
  assert.equal((await student('GET', `/api/notes/${adminNote.id}`)).status, 404);
  assert.equal((await student('PUT', `/api/notes/${adminNote.id}`, { title: 'x' })).status, 404);
  assert.equal((await student('DELETE', `/api/notes/${adminNote.id}`)).status, 404);
  assert.ok((await student('GET', '/api/notes')).body.notes.every((n) => n.id !== adminNote.id));

  assert.equal((await student('GET', '/api/users')).status, 403);
  assert.equal(
    (await student('POST', '/api/users', { username: 'x_y', full_name: 'X', password: 'longenough' }))
      .status,
    403
  );
});

test('admin sees all notes and manages users', async () => {
  const admin = await loginAs('admin', 'Admin@123');

  const all = (await admin('GET', '/api/notes')).body.notes;
  assert.ok(all.some((n) => n.owner_username === 'student1'));

  const created = await admin('POST', '/api/users', {
    username: 'student2',
    full_name: 'Second Student',
    password: 'Secret@123',
  });
  assert.equal(created.status, 201);
  assert.equal(created.body.user.role, 'student');
  assert.equal(created.body.user.password_hash, undefined);
  const userId = created.body.user.id;

  const dup = await admin('POST', '/api/users', {
    username: 'STUDENT2',
    full_name: 'Dup',
    password: 'Secret@123',
  });
  assert.equal(dup.status, 409);
  assert.equal(
    (await admin('POST', '/api/users', { username: 'ok_name', full_name: 'A', password: 'short' }))
      .status,
    400
  );

  const student2 = await loginAs('student2', 'Secret@123');
  const note = (await student2('POST', '/api/notes', { title: 'Mine' })).body.note;
  assert.equal((await admin('GET', `/api/notes?userId=${userId}`)).body.notes.length, 1);
  assert.equal(
    (await admin('PUT', `/api/notes/${note.id}`, { title: 'Edited' })).body.note.title,
    'Edited'
  );

  // Resetting the password signs the user out.
  await admin('PUT', `/api/users/${userId}`, { password: 'Changed@123' });
  assert.equal((await student2('GET', '/api/notes')).status, 401);
  await loginAs('student2', 'Changed@123');

  const me = (await admin('GET', '/api/auth/me')).body.user;
  assert.equal((await admin('PUT', `/api/users/${me.id}`, { role: 'student' })).status, 400);
  assert.equal((await admin('DELETE', `/api/users/${me.id}`)).status, 400);

  // Deleting a user removes their notes.
  assert.equal((await admin('DELETE', `/api/users/${userId}`)).status, 204);
  assert.equal((await admin('GET', `/api/notes/${note.id}`)).status, 404);
});

test('logout ends the session', async () => {
  const student = await loginAs('student1', 'Student@123');
  assert.equal((await student('POST', '/api/auth/logout')).status, 204);
  assert.equal((await student('GET', '/api/auth/me')).status, 401);
});
