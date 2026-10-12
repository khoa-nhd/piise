// Creates the first admin account from ADMIN_USERNAME / ADMIN_PASSWORD.
import fs from 'node:fs';
import path from 'node:path';
import { openDb } from '../src/db.js';
import { hashPassword } from '../src/password.js';
import { newPassword, username } from '../src/validate.js';

const dbPath = process.env.DB_PATH ?? './data/notes.db';

try {
  const name = username(process.env.ADMIN_USERNAME);
  const password = newPassword(process.env.ADMIN_PASSWORD);
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = openDb(dbPath);
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(name)) {
    throw new Error(`User "${name}" already exists; nothing changed`);
  }
  db.prepare('INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)').run(
    name,
    await hashPassword(password),
    'admin',
    new Date().toISOString(),
  );
  console.log(`Admin "${name}" created`);
} catch (err) {
  console.error(`seed-admin failed: ${err.message} (set ADMIN_USERNAME and ADMIN_PASSWORD)`);
  process.exitCode = 1;
}
