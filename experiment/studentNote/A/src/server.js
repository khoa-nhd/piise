const crypto = require('node:crypto');
const app = require('./app');
const db = require('./db');
const { createUser } = require('./users');

const PORT = Number(process.env.PORT) || 3000;

// A fresh database has no way to reach the admin interface, so create the first admin here.
async function ensureAdmin() {
  if (db.prepare(`SELECT 1 FROM users WHERE role = 'admin' LIMIT 1`).get()) return;
  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  await createUser({ username, password, fullName: 'Administrator', role: 'admin' });
  console.log(`Created initial admin account "${username}"`);
  if (!process.env.ADMIN_PASSWORD) {
    console.log(`  Generated password: ${password}`);
    console.log('  It is shown only once. Set ADMIN_PASSWORD before first start to choose your own.');
  }
}

ensureAdmin().then(() => {
  app.listen(PORT, () => console.log(`Student Notes running at http://localhost:${PORT}`));
});
