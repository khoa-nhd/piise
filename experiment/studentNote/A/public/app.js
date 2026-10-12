const $ = (selector) => document.querySelector(selector);

const state = { user: null, notes: [], currentId: null, users: [], editingUserId: null };

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && state.user) showLogin();
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

const isAdmin = () => state.user?.role === 'admin';
const formatDate = (iso) => new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

// ---------- Session ----------

function showLogin() {
  state.user = null;
  $('#app-view').hidden = true;
  $('#login-view').hidden = false;
  $('#login-form').reset();
  $('#login-error').textContent = '';
}

async function showApp(user) {
  state.user = user;
  state.currentId = null;
  $('#login-view').hidden = true;
  $('#app-view').hidden = false;
  $('#whoami').textContent = `${user.full_name} (${user.role})`;
  $('#tabs').hidden = !isAdmin();
  $('#owner-filter').hidden = !isAdmin();
  $('#search').value = '';
  showEditor(null);
  switchTab('notes');
  if (isAdmin()) await loadUsers();
  await loadNotes();
}

$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  $('#login-error').textContent = '';
  try {
    const { user } = await api('POST', '/api/auth/login', {
      username: form.get('username'),
      password: form.get('password'),
    });
    await showApp(user);
  } catch (err) {
    $('#login-error').textContent = err.message;
  }
});

$('#logout').addEventListener('click', async () => {
  await api('POST', '/api/auth/logout').catch(() => {});
  showLogin();
});

function switchTab(tab) {
  $('#notes-view').hidden = tab !== 'notes';
  $('#users-view').hidden = tab !== 'users';
  for (const button of document.querySelectorAll('.tab')) {
    button.classList.toggle('active', button.dataset.tab === tab);
  }
}

$('#tabs').addEventListener('click', (event) => {
  const tab = event.target.dataset.tab;
  if (!tab) return;
  switchTab(tab);
  if (tab === 'users') loadUsers();
  else loadNotes();
});

// ---------- Notes ----------

async function loadNotes() {
  const params = new URLSearchParams();
  const q = $('#search').value.trim();
  if (q) params.set('q', q);
  if (isAdmin() && $('#owner-filter').value) params.set('userId', $('#owner-filter').value);
  try {
    state.notes = (await api('GET', `/api/notes?${params}`)).notes;
  } catch (err) {
    return setStatus(err.message);
  }
  renderNoteList();
}

function renderNoteList() {
  const list = $('#note-list');
  list.replaceChildren(
    ...state.notes.map((note) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.classList.toggle('active', note.id === state.currentId);
      const title = document.createElement('div');
      title.className = 'title';
      title.textContent = note.title;
      const sub = document.createElement('div');
      sub.className = 'sub';
      sub.textContent = isAdmin()
        ? `${note.owner_name} · ${formatDate(note.updated_at)}`
        : formatDate(note.updated_at);
      button.append(title, sub);
      button.addEventListener('click', () => showEditor(note));
      const item = document.createElement('li');
      item.append(button);
      return item;
    })
  );
  $('#note-empty').hidden = state.notes.length > 0;
}

function setStatus(text) {
  $('#note-status').textContent = text;
}

// note === null hides the editor; a note without an id is a new, unsaved one.
function showEditor(note) {
  state.currentId = note?.id ?? null;
  $('#note-form').hidden = !note;
  $('#editor-empty').hidden = !!note;
  setStatus('');
  if (note) {
    $('#note-title').value = note.title;
    $('#note-content').value = note.content;
    $('#note-delete').hidden = !note.id;
    $('#note-meta').textContent = note.id
      ? `${isAdmin() ? `${note.owner_name} (${note.owner_username}) · ` : ''}Updated ${formatDate(note.updated_at)}`
      : 'New note';
  }
  renderNoteList();
}

$('#new-note').addEventListener('click', () => {
  showEditor({ title: '', content: '' });
  $('#note-title').focus();
});

$('#note-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const body = { title: $('#note-title').value, content: $('#note-content').value };
  try {
    const { note } = state.currentId
      ? await api('PUT', `/api/notes/${state.currentId}`, body)
      : await api('POST', '/api/notes', body);
    await loadNotes();
    showEditor(note);
    setStatus('Saved');
  } catch (err) {
    setStatus(err.message);
  }
});

$('#note-delete').addEventListener('click', async () => {
  if (!state.currentId || !confirm('Delete this note? This cannot be undone.')) return;
  try {
    await api('DELETE', `/api/notes/${state.currentId}`);
    showEditor(null);
    await loadNotes();
  } catch (err) {
    setStatus(err.message);
  }
});

let searchTimer;
$('#search').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(loadNotes, 250);
});
$('#owner-filter').addEventListener('change', loadNotes);

// ---------- Users (admin) ----------

async function loadUsers() {
  state.users = (await api('GET', '/api/users')).users;

  const filter = $('#owner-filter');
  const selected = filter.value;
  filter.replaceChildren(
    new Option('All users', ''),
    ...state.users.map((user) => new Option(`${user.full_name} (${user.username})`, user.id))
  );
  filter.value = state.users.some((user) => String(user.id) === selected) ? selected : '';

  $('#user-rows').replaceChildren(
    ...state.users.map((user) => {
      const row = document.createElement('tr');
      for (const value of [
        user.username,
        user.full_name,
        user.role,
        user.note_count,
        formatDate(user.created_at),
      ]) {
        row.insertCell().textContent = value;
      }
      const actions = row.insertCell();
      const edit = document.createElement('button');
      edit.textContent = 'Edit';
      edit.addEventListener('click', () => openUserDialog(user));
      actions.append(edit);
      if (user.id !== state.user.id) {
        const remove = document.createElement('button');
        remove.textContent = 'Delete';
        remove.className = 'danger';
        remove.addEventListener('click', () => deleteUser(user));
        actions.append(remove);
      }
      return row;
    })
  );
}

function openUserDialog(user) {
  const form = $('#user-form');
  form.reset();
  state.editingUserId = user?.id ?? null;
  $('#user-dialog-title').textContent = user ? 'Edit user' : 'Add user';
  $('#password-label').textContent = user ? 'New password (leave blank to keep)' : 'Password';
  $('#user-error').textContent = '';
  form.username.disabled = !!user;
  form.password.required = !user;
  // An admin cannot demote themselves, so don't offer it.
  form.role.disabled = user?.id === state.user.id;
  if (user) {
    form.username.value = user.username;
    form.full_name.value = user.full_name;
    form.role.value = user.role;
  }
  $('#user-dialog').showModal();
}

async function deleteUser(user) {
  const notes = user.note_count === 1 ? '1 note' : `${user.note_count} notes`;
  if (!confirm(`Delete ${user.username} and their ${notes}? This cannot be undone.`)) return;
  try {
    await api('DELETE', `/api/users/${user.id}`);
    await loadUsers();
  } catch (err) {
    alert(err.message);
  }
}

$('#new-user').addEventListener('click', () => openUserDialog(null));
$('#user-cancel').addEventListener('click', () => $('#user-dialog').close());

$('#user-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.target;
  const body = { full_name: form.full_name.value, role: form.role.value };
  if (form.password.value) body.password = form.password.value;
  try {
    if (state.editingUserId) {
      await api('PUT', `/api/users/${state.editingUserId}`, body);
    } else {
      await api('POST', '/api/users', { ...body, username: form.username.value });
    }
    $('#user-dialog').close();
    await loadUsers();
  } catch (err) {
    $('#user-error').textContent = err.message;
  }
});

// ---------- Boot ----------

api('GET', '/api/auth/me').then(({ user }) => showApp(user), showLogin);
