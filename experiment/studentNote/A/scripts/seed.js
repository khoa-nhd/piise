// Creates demo accounts and sample notes for local development. Do not run against a real deployment.
const db = require('../src/db');
const { createUser } = require('../src/users');

const DEMO_USERS = [
  { username: 'admin', password: 'Admin@12345', fullName: 'Administrator', role: 'admin' },
  { username: 'student', password: 'Student@12345', fullName: 'Demo Student', role: 'student' },
];

const DEMO_NOTES = [
  ['Database lecture 3', 'Normal forms: 1NF, 2NF, 3NF.\nRevise functional dependencies before the quiz.'],
  ['Group project', 'Meeting on Friday. Bring the ER diagram and the API draft.'],
];

async function main() {
  for (const demo of DEMO_USERS) {
    if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(demo.username)) {
      console.log(`skip  ${demo.username} (already exists)`);
      continue;
    }
    const user = await createUser(demo);
    if (demo.role === 'student') {
      const insert = db.prepare('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)');
      for (const [title, content] of DEMO_NOTES) insert.run(user.id, title, content);
    }
    console.log(`added ${demo.username} / ${demo.password} (${demo.role})`);
  }
}

main();
