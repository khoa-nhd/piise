const app = document.getElementById('app');
const toastEl = document.getElementById('toast');

let token = localStorage.getItem('token');
let me = null;
let dirty = false; // the open note has unsaved edits
let noteFilterUserId = ''; // admin "All notes" owner filter

// ---------- helpers ----------

// All user-supplied text goes through text nodes here, never innerHTML.
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else if (key in el) el[key] = value;
    else el.setAttribute(key, value);
  }
  el.append(...children.flat().filter((child) => child != null && child !== false));
  return el;
}

async function api(method, path, body) {
  const res = await fetch('/api' + path, {
    method,
    headers: {
      ...(body !== undefined && { 'Content-Type': 'application/json' }),
      ...(token && { Authorization: `Bearer ${token}` }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && me) {
      setSession(null, null);
      renderAuth();
    }
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

function setSession(newToken, user) {
  token = newToken;
  me = user;
  dirty = false;
  noteFilterUserId = '';
  if (token) localStorage.setItem('token', token);
  else localStorage.removeItem('token');
}

let toastTimer;
function toast(message) {
  toastEl.textContent = message;
  toastEl.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.remove('show'), 2500);
}

const formatDate = (iso) => new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

function debounce(fn, ms = 250) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

const canDiscard = () => !dirty || confirm('Discard unsaved changes to this note?');

function openDialog(title, ...children) {
  const dialog = h('dialog', {}, h('h2', { textContent: title }), ...children);
  dialog.addEventListener('close', () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
  return dialog;
}

// fields: [{ name, label, type?, options?, value?, ...input props }]
function formDialog(title, fields, submitLabel, onSubmit) {
  const error = h('p', { className: 'error', role: 'alert' });
  const submit = h('button', { className: 'primary', type: 'submit', textContent: submitLabel });
  const inputs = {};
  const form = h(
    'form',
    {
      onsubmit: async (event) => {
        event.preventDefault();
        submit.disabled = true;
        error.textContent = '';
        try {
          await onSubmit(Object.fromEntries(Object.entries(inputs).map(([name, input]) => [name, input.value])));
          dialog.close();
        } catch (err) {
          error.textContent = err.message;
          submit.disabled = false;
        }
      },
    },
    fields.map(({ name, label, options, ...props }) => {
      inputs[name] = options
        ? h('select', props, options.map((option) => h('option', { value: option, textContent: option })))
        : h('input', { required: true, ...props });
      return h('label', {}, label, inputs[name]);
    }),
    error,
    h('div', { className: 'actions' }, h('button', { type: 'button', textContent: 'Cancel', onclick: () => dialog.close() }), submit)
  );
  const dialog = openDialog(title, form);
}

// ---------- sign in / register ----------

function renderAuth(mode = 'login') {
  const registering = mode === 'register';
  const error = h('p', { className: 'error', role: 'alert' });
  const fullName = h('input', { required: true, maxLength: 100, autocomplete: 'name' });
  const username = h('input', { required: true, minLength: 3, maxLength: 32, autocomplete: 'username' });
  const password = h('input', {
    type: 'password',
    required: true,
    minLength: registering ? 8 : 1,
    maxLength: 128,
    autocomplete: registering ? 'new-password' : 'current-password',
  });
  const submit = h('button', { className: 'primary', type: 'submit', textContent: registering ? 'Create account' : 'Sign in' });

  const form = h(
    'form',
    {
      onsubmit: async (event) => {
        event.preventDefault();
        submit.disabled = true;
        error.textContent = '';
        try {
          const body = { username: username.value, password: password.value };
          if (registering) body.fullName = fullName.value;
          const data = await api('POST', registering ? '/auth/register' : '/auth/login', body);
          setSession(data.token, data.user);
          renderShell();
        } catch (err) {
          error.textContent = err.message;
          submit.disabled = false;
        }
      },
    },
    registering && h('label', {}, 'Full name', fullName),
    h('label', {}, 'Username', username),
    h('label', {}, registering ? 'Password (at least 8 characters)' : 'Password', password),
    error,
    submit
  );

  app.replaceChildren(
    h(
      'div',
      { className: 'auth' },
      h(
        'div',
        { className: 'card' },
        h('h1', { textContent: 'Student Notes' }),
        h('p', { className: 'muted', textContent: registering ? 'Create a student account' : 'Sign in to your notes' }),
        form,
        h(
          'p',
          { className: 'switch muted' },
          registering ? 'Already have an account? ' : 'New student? ',
          h('button', {
            className: 'link',
            type: 'button',
            textContent: registering ? 'Sign in' : 'Create an account',
            onclick: () => renderAuth(registering ? 'login' : 'register'),
          })
        )
      )
    )
  );
  (registering ? fullName : username).focus();
}

// ---------- app shell ----------

function renderShell(initialTab = 'notes') {
  const tabs = [['notes', 'My notes', renderNotes]];
  if (me.role === 'admin') {
    tabs.push(['users', 'Users', renderUsers], ['all-notes', 'All notes', renderAllNotes]);
  }
  const main = h('main');
  const buttons = new Map();

  function show(name) {
    if (!canDiscard()) return;
    dirty = false;
    for (const [tabName, button] of buttons) {
      if (tabName === name) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    }
    tabs.find(([tabName]) => tabName === name)[2](main, show);
  }

  for (const [name, label] of tabs) {
    buttons.set(name, h('button', { type: 'button', textContent: label, onclick: () => show(name) }));
  }

  app.replaceChildren(
    h(
      'header',
      {},
      h('h1', { textContent: 'Student Notes' }),
      h('nav', {}, tabs.length > 1 ? [...buttons.values()] : []),
      h(
        'div',
        { className: 'who' },
        h('span', { textContent: me.fullName }),
        h('span', { className: 'badge', textContent: me.role }),
        h('button', {
          type: 'button',
          textContent: 'Sign out',
          onclick: async () => {
            if (!canDiscard()) return;
            await api('POST', '/auth/logout').catch(() => {});
            setSession(null, null);
            renderAuth();
          },
        })
      )
    ),
    main
  );
  show(initialTab);
}

// ---------- my notes (student + admin) ----------

function renderNotes(main) {
  let notes = [];
  let current = null; // null = nothing open, { id: null } = unsaved new note
  let requestId = 0;

  const search = h('input', { type: 'search', placeholder: 'Search notes', 'aria-label': 'Search notes', oninput: debounce(loadList) });
  const list = h('ul', { className: 'note-list' });
  const editor = h('section', { className: 'panel editor' });

  async function loadList() {
    const id = ++requestId;
    try {
      const data = await api('GET', '/notes?q=' + encodeURIComponent(search.value.trim()));
      if (id !== requestId) return; // a newer search is in flight
      notes = data.notes;
      renderList();
    } catch (err) {
      toast(err.message);
    }
  }

  function renderList() {
    if (!notes.length) {
      list.replaceChildren(h('li', { className: 'empty', textContent: search.value.trim() ? 'No notes match your search.' : 'No notes yet.' }));
      return;
    }
    list.replaceChildren(
      ...notes.map((note) =>
        h(
          'li',
          {},
          h(
            'button',
            { type: 'button', 'aria-current': String(current?.id === note.id), onclick: () => open(note) },
            h('strong', { textContent: note.title }),
            h('span', { textContent: formatDate(note.updatedAt) })
          )
        )
      )
    );
  }

  function open(note) {
    if (!canDiscard()) return;
    dirty = false;
    current = note;
    renderList();
    renderEditor();
  }

  function renderEditor() {
    if (!current) {
      editor.replaceChildren(h('p', { className: 'empty', textContent: 'Select a note, or create a new one.' }));
      return;
    }
    const isNew = current.id === null;
    const markDirty = () => (dirty = true);
    const title = h('input', { value: current.title ?? '', placeholder: 'Title', 'aria-label': 'Title', maxLength: 200, required: true, oninput: markDirty });
    const content = h('textarea', { value: current.content ?? '', placeholder: 'Write your note…', 'aria-label': 'Content', maxLength: 20000, oninput: markDirty });
    const save = h('button', { className: 'primary', type: 'submit', textContent: 'Save' });

    editor.replaceChildren(
      h(
        'form',
        {
          onsubmit: async (event) => {
            event.preventDefault();
            save.disabled = true;
            try {
              const body = { title: title.value, content: content.value };
              const data = isNew ? await api('POST', '/notes', body) : await api('PUT', `/notes/${current.id}`, body);
              dirty = false;
              current = data.note;
              toast('Note saved');
              renderEditor();
              await loadList();
            } catch (err) {
              toast(err.message);
              save.disabled = false;
            }
          },
        },
        title,
        content,
        h(
          'div',
          { className: 'actions' },
          h('span', { className: 'muted', textContent: isNew ? 'New note' : `Last edited ${formatDate(current.updatedAt)}` }),
          !isNew &&
            h('button', {
              className: 'danger',
              type: 'button',
              textContent: 'Delete',
              onclick: async () => {
                if (!confirm(`Delete "${current.title}"? This cannot be undone.`)) return;
                try {
                  await api('DELETE', `/notes/${current.id}`);
                  dirty = false;
                  current = null;
                  toast('Note deleted');
                  renderEditor();
                  await loadList();
                } catch (err) {
                  toast(err.message);
                }
              },
            }),
          save
        )
      )
    );
    if (isNew) title.focus();
  }

  main.replaceChildren(
    h(
      'div',
      { className: 'notes' },
      h(
        'aside',
        { className: 'panel sidebar' },
        h(
          'div',
          { className: 'toolbar' },
          search,
          h('button', { className: 'primary', type: 'button', textContent: 'New note', onclick: () => open({ id: null }) })
        ),
        list
      ),
      editor
    )
  );
  renderEditor();
  loadList();
}

// ---------- admin: users ----------

function renderUsers(main, show) {
  const stats = h('div', { className: 'stats' });
  const tbody = h('tbody');

  async function load() {
    try {
      const [counts, data] = await Promise.all([api('GET', '/admin/stats'), api('GET', '/admin/users')]);
      stats.replaceChildren(
        ...[
          ['Students', counts.students],
          ['Admins', counts.admins],
          ['Notes', counts.notes],
        ].map(([label, value]) => h('div', { className: 'panel stat' }, h('strong', { textContent: value }), h('span', { className: 'muted', textContent: label })))
      );
      tbody.replaceChildren(...data.users.map(row));
    } catch (err) {
      toast(err.message);
    }
  }

  function row(user) {
    const isSelf = user.id === me.id;
    const role = h(
      'select',
      {
        'aria-label': `Role for ${user.username}`,
        disabled: isSelf,
        onchange: async () => {
          try {
            await api('PUT', `/admin/users/${user.id}`, { role: role.value });
            toast(`${user.username} is now ${role.value === 'admin' ? 'an admin' : 'a student'}`);
          } catch (err) {
            toast(err.message);
          }
          load();
        },
      },
      ['student', 'admin'].map((value) => h('option', { value, textContent: value, selected: value === user.role }))
    );
    return h(
      'tr',
      {},
      h('td', {}, user.fullName, isSelf && h('span', { className: 'muted', textContent: ' (you)' })),
      h('td', { textContent: user.username }),
      h('td', {}, role),
      h(
        'td',
        {},
        h('button', {
          className: 'link',
          type: 'button',
          textContent: String(user.noteCount),
          title: `View notes by ${user.username}`,
          onclick: () => {
            noteFilterUserId = String(user.id);
            show('all-notes');
          },
        })
      ),
      h('td', { textContent: formatDate(user.createdAt) }),
      h(
        'td',
        { className: 'actions' },
        h('button', {
          type: 'button',
          textContent: 'Reset password',
          onclick: () =>
            formDialog(
              `Reset password for ${user.username}`,
              [{ name: 'password', label: 'New password (at least 8 characters)', type: 'password', minLength: 8, maxLength: 128, autocomplete: 'new-password' }],
              'Reset password',
              async ({ password }) => {
                await api('PUT', `/admin/users/${user.id}`, { password });
                toast('Password reset');
              }
            ),
        }),
        h('button', {
          className: 'danger',
          type: 'button',
          textContent: 'Delete',
          disabled: isSelf,
          onclick: async () => {
            if (!confirm(`Delete ${user.username} and their ${user.noteCount} note(s)? This cannot be undone.`)) return;
            try {
              await api('DELETE', `/admin/users/${user.id}`);
              toast('User deleted');
            } catch (err) {
              toast(err.message);
            }
            load();
          },
        })
      )
    );
  }

  const addUser = () =>
    formDialog(
      'Add user',
      [
        { name: 'fullName', label: 'Full name', maxLength: 100 },
        { name: 'username', label: 'Username', minLength: 3, maxLength: 32, autocomplete: 'off' },
        { name: 'password', label: 'Password (at least 8 characters)', type: 'password', minLength: 8, maxLength: 128, autocomplete: 'new-password' },
        { name: 'role', label: 'Role', options: ['student', 'admin'] },
      ],
      'Add user',
      async (values) => {
        await api('POST', '/admin/users', values);
        toast('User added');
        load();
      }
    );

  main.replaceChildren(
    stats,
    h('div', { className: 'toolbar' }, h('h2', { textContent: 'Users' }), h('button', { className: 'primary', type: 'button', textContent: 'Add user', onclick: addUser })),
    h(
      'div',
      { className: 'panel table-wrap' },
      h(
        'table',
        {},
        h('thead', {}, h('tr', {}, ['Name', 'Username', 'Role', 'Notes', 'Joined', ''].map((text) => h('th', { textContent: text })))),
        tbody
      )
    )
  );
  load();
}

// ---------- admin: all notes ----------

function renderAllNotes(main) {
  let requestId = 0;
  const search = h('input', { type: 'search', placeholder: 'Search all notes', 'aria-label': 'Search all notes', oninput: debounce(load) });
  const owner = h(
    'select',
    {
      'aria-label': 'Filter by owner',
      onchange: () => {
        noteFilterUserId = owner.value;
        load();
      },
    },
    h('option', { value: '', textContent: 'All users' })
  );
  const tbody = h('tbody');

  async function load() {
    const id = ++requestId;
    const params = new URLSearchParams({ q: search.value.trim() });
    if (noteFilterUserId) params.set('userId', noteFilterUserId);
    try {
      const data = await api('GET', '/admin/notes?' + params);
      if (id !== requestId) return;
      tbody.replaceChildren(
        ...(data.notes.length ? data.notes.map(row) : [h('tr', {}, h('td', { className: 'empty', colSpan: 4, textContent: 'No notes found.' }))])
      );
    } catch (err) {
      toast(err.message);
    }
  }

  function view(note) {
    const dialog = openDialog(
      note.title,
      h('p', { className: 'muted', textContent: `${note.owner.fullName} (${note.owner.username}) · edited ${formatDate(note.updatedAt)}` }),
      h('pre', { textContent: note.content || '(empty note)' }),
      h('div', { className: 'actions' }, h('button', { type: 'button', textContent: 'Close', onclick: () => dialog.close() }))
    );
  }

  function row(note) {
    return h(
      'tr',
      {},
      h('td', { className: 'clip' }, h('button', { className: 'link', type: 'button', textContent: note.title, onclick: () => view(note) })),
      h('td', { textContent: `${note.owner.fullName} (${note.owner.username})` }),
      h('td', { textContent: formatDate(note.updatedAt) }),
      h(
        'td',
        { className: 'actions' },
        h('button', { type: 'button', textContent: 'View', onclick: () => view(note) }),
        h('button', {
          className: 'danger',
          type: 'button',
          textContent: 'Delete',
          onclick: async () => {
            if (!confirm(`Delete "${note.title}" by ${note.owner.username}? This cannot be undone.`)) return;
            try {
              await api('DELETE', `/admin/notes/${note.id}`);
              toast('Note deleted');
            } catch (err) {
              toast(err.message);
            }
            load();
          },
        })
      )
    );
  }

  main.replaceChildren(
    h('div', { className: 'toolbar' }, h('h2', { textContent: 'All notes' }), owner, search),
    h(
      'div',
      { className: 'panel table-wrap' },
      h('table', {}, h('thead', {}, h('tr', {}, ['Title', 'Owner', 'Last edited', ''].map((text) => h('th', { textContent: text })))), tbody)
    )
  );

  api('GET', '/admin/users')
    .then((data) => {
      owner.append(...data.users.map((user) => h('option', { value: String(user.id), textContent: `${user.fullName} (${user.username})` })));
      owner.value = noteFilterUserId;
    })
    .catch((err) => toast(err.message));
  load();
}

// ---------- start ----------

window.addEventListener('beforeunload', (event) => {
  if (dirty) event.preventDefault();
});

(async () => {
  if (token) {
    try {
      me = (await api('GET', '/auth/me')).user;
      return renderShell();
    } catch {
      setSession(null, null);
    }
  }
  renderAuth();
})();
