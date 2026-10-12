const path = require('node:path');
const { openDb } = require('./src/db');
const { createApp } = require('./src/app');

const PORT = Number(process.env.PORT) || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'notes.db');

const app = createApp(openDb(DB_PATH));
app.listen(PORT, () => console.log(`Student Notes running at http://localhost:${PORT}`));
