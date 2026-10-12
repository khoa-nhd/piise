const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { hashPassword } = require('./passwords');

function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');
  db.exec(fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8'));
  seed(db);
  return db;
}

// First run only: create one admin and one student so the app is usable.
function seed(db) {
  if (db.prepare('SELECT COUNT(*) AS n FROM users').get().n > 0) return;
  const insertUser = db.prepare(
    'INSERT INTO users (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)'
  );
  insertUser.run(
    'admin',
    hashPassword(process.env.SEED_ADMIN_PASSWORD || 'Admin@123'),
    'Administrator',
    'admin'
  );
  const student = insertUser.run(
    'student1',
    hashPassword(process.env.SEED_STUDENT_PASSWORD || 'Student@123'),
    'Sample Student',
    'student'
  );
  db.prepare('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)').run(
    Number(student.lastInsertRowid),
    'Welcome to Student Notes',
    'This is your first note. Edit it, delete it, or create a new one.'
  );
}

module.exports = { openDb };
