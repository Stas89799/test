const express = require('express');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/authRoutes');
const profileRoutes = require('./routes/profileRoutes');
const pool = require('./db/connection');
const logger = require('./utils/logger');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cookieParser());

// Тест соединения с базой данных
(async () => {
  try {
    await pool.execute('SELECT 1');
    logger.info('Database connected successfully.');
  } catch (error) {
    logger.error('Database connection error: ', error.message);
  }
})();

// Роуты
app.use('/api/auth', authRoutes);
app.use('/api/profile', profileRoutes);

// Обработка ошибок
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

// Запуск сервера
app.listen(PORT, () => {
  logger.info(`Server is running on port ${PORT}`);
});