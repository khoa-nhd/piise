import fs from 'node:fs';
import path from 'node:path';
import { createApp } from './app.js';
import { openDb } from './db.js';

const env = process.env;
const port = Number(env.PORT ?? 3000);
const host = env.HOST ?? '127.0.0.1';
const dbPath = env.DB_PATH ?? './data/notes.db';
const ttlMinutes = Number(env.SESSION_TTL_MINUTES ?? 60);

if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('PORT is invalid');
if (!(ttlMinutes > 0)) throw new Error('SESSION_TTL_MINUTES is invalid');

fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const app = createApp({
  db: openDb(dbPath),
  cookieSecure: env.COOKIE_SECURE ? env.COOKIE_SECURE === 'true' : env.NODE_ENV === 'production',
  sessionTtlMs: ttlMinutes * 60 * 1000,
  trustProxy: env.TRUST_PROXY ? Number(env.TRUST_PROXY) : false,
});

app.listen(port, host, () => {
  console.log(`Student notes listening on http://${host}:${port}`);
});
