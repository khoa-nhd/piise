# Student Notes

A notes application with login, notes CRUD, and separate student and admin interfaces.

- **Backend:** Node.js + Express 5
- **Database:** SQLite (Node's built-in `node:sqlite`, no database server needed)
- **Frontend:** plain HTML/CSS/JS served by the same app

## Run

Requires Node.js 22.13 or newer.

```bash
npm install
```

```bash
npm start
```

Open http://localhost:3000. The database is created at `data/notes.db` on first start and
seeded with two accounts:

| Role    | Username   | Password      |
| ------- | ---------- | ------------- |
| Admin   | `admin`    | `Admin@123`   |
| Student | `student1` | `Student@123` |

These are demo defaults. Set `SEED_ADMIN_PASSWORD` / `SEED_STUDENT_PASSWORD` before the first
start to choose your own, or change them from the admin Users screen afterwards.

| Variable   | Default         | Purpose                                         |
| ---------- | --------------- | ----------------------------------------------- |
| `PORT`     | `3000`          | HTTP port                                       |
| `DB_PATH`  | `data/notes.db` | SQLite file                                     |
| `NODE_ENV` | –               | `production` marks the session cookie `Secure`  |

Run the tests (in-memory database):

```bash
npm test
```

## Roles

| Capability                               | Student | Admin |
| ---------------------------------------- | :-----: | :---: |
| Sign in / sign out                       |    ✔    |   ✔   |
| Create, read, update, delete own notes   |    ✔    |   ✔   |
| Read, update, delete any user's notes    |         |   ✔   |
| Create, edit, delete users, reset passwords |      |   ✔   |

There is no self-registration: admins create accounts. An admin cannot delete their own account
or remove their own admin role.

## Database

Defined in [schema.sql](schema.sql).

**users**

| Column          | Type    | Notes                                          |
| --------------- | ------- | ---------------------------------------------- |
| `id`            | INTEGER | Primary key                                    |
| `username`      | TEXT    | Unique, case-insensitive                       |
| `password_hash` | TEXT    | `scrypt$<salt>$<hash>`                         |
| `full_name`     | TEXT    |                                                |
| `role`          | TEXT    | `student` or `admin`                           |
| `created_at`    | TEXT    | ISO 8601 UTC                                   |

**notes**

| Column       | Type    | Notes                                             |
| ------------ | ------- | ------------------------------------------------- |
| `id`         | INTEGER | Primary key                                       |
| `user_id`    | INTEGER | Owner, FK → `users.id`, `ON DELETE CASCADE`       |
| `title`      | TEXT    | 1–200 characters                                  |
| `content`    | TEXT    | Up to 20,000 characters                           |
| `created_at` | TEXT    | ISO 8601 UTC                                      |
| `updated_at` | TEXT    | ISO 8601 UTC                                      |

**sessions**

| Column       | Type    | Notes                                             |
| ------------ | ------- | ------------------------------------------------- |
| `token_hash` | TEXT    | Primary key, SHA-256 of the session token         |
| `user_id`    | INTEGER | FK → `users.id`, `ON DELETE CASCADE`              |
| `expires_at` | INTEGER | Unix time in milliseconds                         |

## API

All bodies are JSON. Authentication is a session cookie (`sid`, HttpOnly, SameSite=Strict,
7 days) set by login. Errors are returned as `{ "error": "message" }`.

| Status | Meaning                                              |
| ------ | ---------------------------------------------------- |
| 400    | Validation failed                                    |
| 401    | Not signed in, or wrong credentials                  |
| 403    | Signed in but not an admin                           |
| 404    | Not found (including another student's note)         |
| 409    | Username already taken                               |
| 429    | Too many failed logins (10 per 15 minutes per IP)    |

### Auth

| Method | Path               | Body                     | Response            |
| ------ | ------------------ | ------------------------ | ------------------- |
| POST   | `/api/auth/login`  | `{ username, password }` | `200 { user }`      |
| POST   | `/api/auth/logout` | –                        | `204`               |
| GET    | `/api/auth/me`     | –                        | `200 { user }`      |

`user` is `{ id, username, full_name, role }`.

### Notes (signed in)

| Method | Path             | Body                   | Response             |
| ------ | ---------------- | ---------------------- | -------------------- |
| GET    | `/api/notes`     | –                      | `200 { notes: [] }`  |
| POST   | `/api/notes`     | `{ title, content? }`  | `201 { note }`       |
| GET    | `/api/notes/:id` | –                      | `200 { note }`       |
| PUT    | `/api/notes/:id` | `{ title, content? }`  | `200 { note }`       |
| DELETE | `/api/notes/:id` | –                      | `204`                |

`GET /api/notes` returns the caller's notes, newest first. Admins get every user's notes.
Query parameters: `q` (search title and content), `userId` (admin only, filter by owner).

`note` is `{ id, title, content, created_at, updated_at, user_id, owner_username, owner_name }`.

### Users (admin only)

| Method | Path             | Body                                          | Response            |
| ------ | ---------------- | --------------------------------------------- | ------------------- |
| GET    | `/api/users`     | –                                             | `200 { users: [] }` |
| POST   | `/api/users`     | `{ username, full_name, password, role? }`    | `201 { user }`      |
| PUT    | `/api/users/:id` | `{ full_name?, role?, password? }`            | `200 { user }`      |
| DELETE | `/api/users/:id` | –                                             | `204`               |

`user` is `{ id, username, full_name, role, created_at, note_count }`. Usernames are 3–32
characters (letters, digits, `_`, `.`); passwords are at least 8 characters. Resetting a password
signs that user out everywhere; deleting a user deletes their notes.
