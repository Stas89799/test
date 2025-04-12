require('dotenv').config();
const https = require('https');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const winston = require('winston');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const authController = require('./authController');
const pool = require('./db/connection');

const app = express();

// Настройка HTTPS
const httpsOptions = {
  key: fs.readFileSync(process.env.SSL_KEY_PATH),
  cert: fs.readFileSync(process.env.SSL_CERT_PATH)
};

// Логирование
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

// Middleware
app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
const csrfProtection = csrf({ cookie: true });

// CSRF endpoint
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Маршруты аутентификации
app.post('/api/auth/register', authController.register);
app.post('/api/auth/login', authController.login);
app.post('/api/auth/refresh', authController.refresh);
app.post('/api/auth/logout', authController.logout);

// Защищенные маршруты с CSRF
app.post('/saveProfile', csrfProtection, authController.authMiddleware, authController.saveProfile);

// Обработка ошибок CSRF
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    logger.error('CSRF token validation failed');
    return res.status(403).json({ message: 'Недействительный CSRF-токен' });
  }
  next(err);
});

// Запуск HTTPS-сервера
https.createServer(httpsOptions, app).listen(process.env.PORT, () => {
  logger.info(`HTTPS server running on port ${process.env.PORT}`);
});