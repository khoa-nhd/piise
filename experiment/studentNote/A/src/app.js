const path = require('node:path');
const express = require('express');
const { HttpError } = require('./validate');

const app = express();
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
  next();
});

app.use(express.json({ limit: '100kb' }));

app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});
app.use('/api/auth', require('./routes/auth'));
app.use('/api/notes', require('./routes/notes'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api', (req, res) => {
  throw new HttpError(404, 'Not found');
});

app.use(express.static(path.join(__dirname, '..', 'public')));

app.use((err, req, res, next) => {
  // HttpError and body-parser errors carry a client-safe status and message.
  const status = err.status >= 400 && err.status < 500 ? err.status : 500;
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? 'Internal server error' : err.message });
});

module.exports = app;
