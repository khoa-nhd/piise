'use strict';

// All user-controlled text is written with textContent, never innerHTML.

const $ = (id) => document.getElementById(id);
const state = { user: null, csrfToken: null, editingId: null };

function el(tag, props = {}, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function showMessage(text, isError = false) {
  const box = $('message');
  box.textContent = text;
  box.classList.toggle('error', isError);
  box.hidden = !text;
}

async function api(method, path, body) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (state.csrfToken) headers['X-CSRF-Token'] = state.csrfToken;
  const res = await fetch('/api' + path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    if (res.status === 401 && state.user) setSession(null);
    throw new Error((data && data.error) || 'Request failed');
  }
  return data;
}

// Wraps a handler so failures are shown to the user instead of being swallowed.
function guarded(fn) {
  return async (event) => {
    if (event) event.preventDefault();
    try {
      showMessage('');
      await fn(event);
    } catch (err) {
      showMessage(err.message, true);
    }
  };
}

const formValues = (form) => Object.fromEntries(new FormData(form));
const when = (iso) => new Date(iso).toLocaleString();

function setSession(session) {
  state.user = session ? session.user : null;
  state.csrfToken = session ? session.csrfToken : null;
  $('auth-view').hidden = !!state.user;
  $('app-view').hidden = !state.user;
  $('session').hidden = !state.user;
  $('admin-view').hidden = !state.user || state.user.role !== 'admin';
  $('whoami').textContent = state.user ? `${state.user.username} (${state.user.role})` : '';
  resetNoteForm();
}

function resetNoteForm() {
  state.editingId = null;
  $('note-form').reset();
  $('note-form-heading').textContent = 'New note';
  $('note-cancel').hidden = true;
}

function noteCard(note, actions, ownerText) {
  const meta = `${ownerText ? ownerText + ' · ' : ''}updated ${when(note.updatedAt)}`;
  return el(
    'li',
    {},
    el('h3', { textContent: note.title }),
    el('div', { className: 'meta', textContent: meta }),
    el('pre', { textContent: note.content }),
    el('div', { className: 'actions' }, ...actions),
  );
}

async function loadNotes() {
  const { notes } = await api('GET', '/notes');
  const list = $('notes');
  list.replaceChildren(
    ...notes.map((note) =>
      noteCard(note, [
        el('button', {
          className: 'secondary',
          textContent: 'Edit',
          onclick: () => {
            state.editingId = note.id;
            $('note-form').elements.title.value = note.title;
            $('note-form').elements.content.value = note.content;
            $('note-form-heading').textContent = 'Edit note';
            $('note-cancel').hidden = false;
            $('note-form').scrollIntoView();
          },
        }),
        el('button', {
          className: 'danger',
          textContent: 'Delete',
          onclick: guarded(async () => {
            if (!confirm('Delete this note?')) return;
            await api('DELETE', `/notes/${note.id}`);
            if (state.editingId === note.id) resetNoteForm();
            await refresh();
          }),
        }),
      ]),
    ),
  );
  if (!notes.length) list.append(el('li', { className: 'meta', textContent: 'No notes yet.' }));
}

async function loadAdmin() {
  const [{ users }, { notes }] = await Promise.all([api('GET', '/admin/users'), api('GET', '/admin/notes')]);

  $('users').replaceChildren(
    ...users.map((user) => {
      const isSelf = user.id === state.user.id;
      const select = el(
        'select',
        { disabled: isSelf },
        ...['student', 'admin'].map((r) => el('option', { value: r, textContent: r, selected: r === user.role })),
      );
      select.onchange = guarded(async () => {
        try {
          await api('PATCH', `/admin/users/${user.id}/role`, { role: select.value });
        } finally {
          await loadAdmin();
        }
      });
      const remove = el('button', {
        className: 'danger',
        textContent: 'Delete',
        disabled: isSelf,
        onclick: guarded(async () => {
          if (!confirm(`Delete ${user.username} and all of their notes?`)) return;
          await api('DELETE', `/admin/users/${user.id}`);
          await loadAdmin();
        }),
      });
      return el(
        'tr',
        {},
        el('td', { textContent: String(user.id) }),
        el('td', { textContent: user.username }),
        el('td', {}, select),
        el('td', { textContent: when(user.createdAt) }),
        el('td', {}, remove),
      );
    }),
  );

  const list = $('all-notes');
  list.replaceChildren(
    ...notes.map((note) =>
      noteCard(
        note,
        [
          el('button', {
            className: 'danger',
            textContent: 'Delete',
            onclick: guarded(async () => {
              if (!confirm('Delete this note?')) return;
              await api('DELETE', `/admin/notes/${note.id}`);
              await refresh();
            }),
          }),
        ],
        `by ${note.ownerUsername}`,
      ),
    ),
  );
  if (!notes.length) list.append(el('li', { className: 'meta', textContent: 'No notes.' }));
}

async function refresh() {
  await loadNotes();
  if (state.user && state.user.role === 'admin') await loadAdmin();
}

$('login-form').onsubmit = guarded(async (e) => {
  const session = await api('POST', '/auth/login', formValues(e.target));
  e.target.reset();
  setSession(session);
  await refresh();
});

$('register-form').onsubmit = guarded(async (e) => {
  await api('POST', '/auth/register', formValues(e.target));
  e.target.reset();
  showMessage('Account created. You can now log in.');
});

$('logout').onclick = guarded(async () => {
  await api('POST', '/auth/logout');
  setSession(null);
});

$('note-form').onsubmit = guarded(async (e) => {
  const body = formValues(e.target);
  if (state.editingId) await api('PUT', `/notes/${state.editingId}`, body);
  else await api('POST', '/notes', body);
  resetNoteForm();
  await refresh();
});

$('note-cancel').onclick = resetNoteForm;

$('user-form').onsubmit = guarded(async (e) => {
  await api('POST', '/admin/users', formValues(e.target));
  e.target.reset();
  await loadAdmin();
});

(async () => {
  try {
    setSession(await api('GET', '/auth/me'));
    await refresh();
  } catch {
    setSession(null);
  }
})();
