# Student Notes

A notes application for students with login, note create/read/update/delete, a SQLite database, and separate student and admin interfaces.

- **Backend:** Node.js + Express 5, SQLite through the built-in `node:sqlite` module (no native build step)
- **Frontend:** plain HTML/CSS/JavaScript single-page app served from `public/`
- **Requires:** Node.js 22.13 or newer

## Run

```bash
npm install
```

```bash
npm run seed
```

```bash
npm start
```

Then open http://localhost:3000.

`npm run seed` is optional and for local development only. It creates two demo accounts:

| Username  | Password        | Role    |
| --------- | --------------- | ------- |
| `admin`   | `Admin@12345`   | admin   |
| `student` | `Student@12345` | student |

Without seeding, the first `npm start` creates an `admin` account and prints a generated password once. Set `ADMIN_USERNAME` / `ADMIN_PASSWORD` before the first start to choose your own.

| Variable         | Default         | Purpose                               |
| ---------------- | --------------- | ------------------------------------- |
| `PORT`           | `3000`          | HTTP port                             |
| `DB_PATH`        | `data/notes.db` | SQLite file (`:memory:` for tests)    |
| `ADMIN_USERNAME` | `admin`         | First admin, created only if none exist |
| `ADMIN_PASSWORD` | generated       | Password for that first admin         |

Run the API tests with `npm test`.

## Roles

| Capability                                   | Student | Admin |
| -------------------------------------------- | :-----: | :---: |
| Register / sign in / sign out                |    ✓    |   ✓   |
| Create, read, update, delete **own** notes   |    ✓    |   ✓   |
| Search own notes                             |    ✓    |   ✓   |
| List, add, delete users; change role; reset password |   |   ✓   |
| View and delete **any** user's notes         |         |   ✓   |

Admins cannot edit other users' notes, delete their own account, or remove their own admin role (so there is always at least one admin).

## Database

Defined in [src/schema.sql](src/schema.sql). Timestamps are ISO-8601 UTC strings.

**users**

| Column          | Type    | Notes                                         |
| --------------- | ------- | --------------------------------------------- |
| `id`            | INTEGER | primary key                                   |
| `username`      | TEXT    | unique, case-insensitive                      |
| `password_hash` | TEXT    | `scrypt$<salt>$<hash>`                        |
| `full_name`     | TEXT    |                                               |
| `role`          | TEXT    | `student` (default) or `admin`                |
| `created_at`    | TEXT    |                                               |

**notes**

| Column       | Type    | Notes                                    |
| ------------ | ------- | ---------------------------------------- |
| `id`         | INTEGER | primary key                              |
| `user_id`    | INTEGER | → `users.id`, `ON DELETE CASCADE`        |
| `title`      | TEXT    | 1–200 characters                         |
| `content`    | TEXT    | up to 20 000 characters                  |
| `created_at` | TEXT    |                                          |
| `updated_at` | TEXT    |                                          |

**sessions**

| Column       | Type    | Notes                                    |
| ------------ | ------- | ---------------------------------------- |
| `token_hash` | TEXT    | primary key, SHA-256 of the bearer token |
| `user_id`    | INTEGER | → `users.id`, `ON DELETE CASCADE`        |
| `expires_at` | TEXT    | 7 days after login                       |
| `created_at` | TEXT    |                                          |

## API

All requests and responses are JSON. Authenticated routes need `Authorization: Bearer <token>`. Errors are `{ "error": "message" }`.

| Status | Meaning                                        |
| ------ | ---------------------------------------------- |
| 400    | Validation failed                              |
| 401    | Missing, invalid or expired token; bad login   |
| 403    | Admin role required                            |
| 404    | Not found (including another user's note)      |
| 409    | Username already taken                         |
| 429    | Too many failed logins (10 per 15 minutes)     |

### Auth

| Method | Path                 | Body                               | Response                    |
| ------ | -------------------- | ---------------------------------- | --------------------------- |
| POST   | `/api/auth/register` | `{ username, password, fullName }` | `201 { token, user }` — always a student |
| POST   | `/api/auth/login`    | `{ username, password }`           | `200 { token, user }`       |
| POST   | `/api/auth/logout`   | –                                  | `204`                       |
| GET    | `/api/auth/me`       | –                                  | `200 { user }`              |

`user` is `{ id, username, fullName, role, createdAt }`. Usernames are 3–32 characters of `A–Z a–z 0–9 _ . -`; passwords are 8–128 characters.

### Notes (own notes only)

| Method | Path             | Body                 | Response            |
| ------ | ---------------- | -------------------- | ------------------- |
| GET    | `/api/notes?q=`  | –                    | `200 { notes }` — newest first; `q` searches title and content |
| POST   | `/api/notes`     | `{ title, content? }` | `201 { note }`     |
| GET    | `/api/notes/:id` | –                    | `200 { note }`      |
| PUT    | `/api/notes/:id` | `{ title, content? }` | `200 { note }`     |
| DELETE | `/api/notes/:id` | –                    | `204`               |

`note` is `{ id, userId, title, content, createdAt, updatedAt }`.

### Admin

| Method | Path                           | Body                                      | Response                |
| ------ | ------------------------------ | ----------------------------------------- | ----------------------- |
| GET    | `/api/admin/stats`             | –                                         | `200 { users, admins, students, notes }` |
| GET    | `/api/admin/users`             | –                                         | `200 { users }` — each with `noteCount` |
| POST   | `/api/admin/users`             | `{ username, password, fullName, role? }` | `201 { user }`          |
| PUT    | `/api/admin/users/:id`         | any of `{ fullName, role, password }`     | `200 { user }` — a new password signs the user out |
| DELETE | `/api/admin/users/:id`         | –                                         | `204` — also deletes their notes |
| GET    | `/api/admin/notes?q=&userId=`  | –                                         | `200 { notes }` — each with `owner { id, username, fullName }` |
| DELETE | `/api/admin/notes/:id`         | –                                         | `204`                   |

## Project layout

```
src/
  server.js        entry point; creates the first admin, starts listening
  app.js           Express app, security headers, error handling
  db.js            opens SQLite and applies schema.sql
  schema.sql       database schema
  auth.js          password hashing, sessions, auth middleware
  users.js         user creation
  validate.js      input validation
  routes/          auth, notes and admin endpoints
public/            single-page frontend
scripts/seed.js    demo accounts and sample notes
test/api.test.js   API tests
```
