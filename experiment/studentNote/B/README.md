# Student Notes

Students log in and create, read, update and delete their own notes. Admins manage users and can view and delete any note.

Stack: Node.js 24, Express 5 (the only dependency), SQLite via the built-in `node:sqlite`, password hashing via the built-in `crypto.scrypt`, tests via the built-in `node:test`. The frontend is static HTML/CSS/JS in `public/`.

## Run

```bash
npm install
```

Copy `.env.example` to `.env`, set `ADMIN_USERNAME` and `ADMIN_PASSWORD` (10+ characters), then:

```bash
npm run seed-admin
```

```bash
npm start
```

Open http://127.0.0.1:3000. Students register themselves on the login page; admins are created only by `seed-admin` or by another admin.

```bash
npm test
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` / `HOST` | `3000` / `127.0.0.1` | Listen address |
| `DB_PATH` | `./data/notes.db` | SQLite file |
| `COOKIE_SECURE` | `true` if `NODE_ENV=production`, else `false` | `Secure`, `__Host-` prefixed session cookie. Must be `true` over HTTPS |
| `SESSION_TTL_MINUTES` | `60` | Absolute session lifetime |
| `TRUST_PROXY` | unset | Number of reverse proxies in front of the app |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | none | Read only by `npm run seed-admin` |

## API

All bodies are JSON. Errors are `{ "error": "message" }`. Every write made with a session needs the `X-CSRF-Token` header (value returned by login and `/api/auth/me`). Unknown body fields are rejected with 400.

| Method | Path | Access | Body | Success |
| --- | --- | --- | --- | --- |
| POST | `/api/auth/register` | public | `username`, `password` | 201 `{ user }` (always a student) |
| POST | `/api/auth/login` | public | `username`, `password` | 200 `{ user, csrfToken }` + session cookie |
| POST | `/api/auth/logout` | session | | 204 |
| GET | `/api/auth/me` | session | | 200 `{ user, csrfToken }` |
| GET | `/api/notes` | session | | 200 `{ notes }` (own notes only) |
| POST | `/api/notes` | session | `title`, `content` | 201 `{ note }` |
| GET | `/api/notes/:id` | owner | | 200 `{ note }` |
| PUT | `/api/notes/:id` | owner | `title`, `content` | 200 `{ note }` |
| DELETE | `/api/notes/:id` | owner | | 204 |
| GET | `/api/admin/users` | admin | | 200 `{ users }` |
| POST | `/api/admin/users` | admin | `username`, `password`, `role` | 201 `{ user }` |
| PATCH | `/api/admin/users/:id/role` | admin, not self | `role` | 200 `{ user }` |
| DELETE | `/api/admin/users/:id` | admin, not self | | 204 (also deletes their notes) |
| GET | `/api/admin/notes` | admin | | 200 `{ notes }` with `ownerId`, `ownerUsername` |
| DELETE | `/api/admin/notes/:id` | admin | | 204 |

Shapes: `user` = `{ id, username, role }` (admin endpoints add `createdAt`); `note` = `{ id, title, content, createdAt, updatedAt }`.

Rules: username 3-32 chars of `A-Z a-z 0-9 _ . -`, unique case-insensitively; password 10-128 chars; title 1-200 chars after trimming; content up to 10,000 chars; role `student` or `admin`; 500 notes per user; request bodies up to 50 kB. A note that belongs to someone else returns 404, the same as a missing note.

## Database

Defined in `src/db.js`; created automatically on first start.

- `users(id, username UNIQUE NOCASE, password_hash, role CHECK IN ('student','admin'), created_at)`
- `notes(id, user_id -> users ON DELETE CASCADE, title, content, created_at, updated_at)`
- `sessions(token_hash PK, user_id -> users ON DELETE CASCADE, csrf_token, expires_at)`

## Security design

- Passwords: scrypt (N=2^15, r=8, p=3) with a per-user random salt.
- Sessions: 256-bit random token in an `HttpOnly; SameSite=Strict` cookie; only its SHA-256 is stored. New token on every login, row deleted on logout, absolute expiry. Role changes and user deletion revoke that user's sessions.
- CSRF: per-session token header plus an `Origin` check on all writes.
- Authorization: user and role are re-read from the database on each request; note queries are always scoped by the session user's id; admin routes sit behind a single role check.
- Login throttling: 5 failures per IP + username per 15 minutes; registration: 20 per IP per hour (both in memory).
- All SQL uses prepared statements with bound parameters. The frontend renders user content with `textContent` only, under a CSP with no inline script.
- Errors return a generic message; details are logged server-side only.

## Known limitations

- No HTTPS termination in the app. Deploy behind a TLS proxy and set `COOKIE_SECURE=true` and `TRUST_PROXY`.
- Rate limits are in memory: they reset on restart and are not shared between processes.
- No password reset, password change, email verification or MFA.
- Registration reveals whether a username is taken (409).
- Admins can read the content of every note; admin actions are not audit-logged.
- List endpoints are not paginated.
- `node:sqlite` is still flagged as a release candidate in Node 24.
