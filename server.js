require('dotenv').config();
const https = require('https');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const logger = require('./utils/logger'); // Исправленный импорт
const pool = require('./db/connection');
const authController = require('./authController');

const app = express();

// HTTPS-конфиг
const httpsOptions = {
  key: fs.readFileSync(process.env.SSL_KEY_PATH),
  cert: fs.readFileSync(process.env.SSL_CERT_PATH)
};

// Middleware
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }));
app.use(express.json());
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });

// CSRF-токен
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Маршруты
app.post('/api/auth/register', csrfProtection, authController.register); // Добавлена CSRF-защита
app.post('/api/auth/login', csrfProtection, authController.login);
app.post('/api/auth/refresh', authController.refresh);
app.post('/api/auth/logout', authController.logout);

// Обработка ошибок
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    logger.error('CSRF validation failed');
    return res.status(403).json({ message: 'Invalid CSRF token' });
  }
  logger.error(err.stack);
  res.status(500).send('Server error');
});

// Запуск сервера
https.createServer(httpsOptions, app).listen(process.env.PORT, () => {
  logger.info(`HTTPS server started on port ${process.env.PORT}`);
});
