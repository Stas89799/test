require('dotenv').config();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db/connection');
const logger = require('./logger');

const refreshTokens = new Map();

// Валидация пароля
const validatePassword = (password) => {
  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()])[A-Za-z\d!@#$%^&*()]{8,}$/;
  if (!passwordRegex.test(password)) {
    throw new Error('Пароль должен содержать минимум 8 символов, одну заглавную букву, цифру и спецсимвол');
  }
};

// Генерация токенов с обновленными настройками
const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ userId }, process.env.REFRESH_SECRET, { expiresIn: '7d' }); // Срок действия refresh токена
  refreshTokens.set(refreshToken, userId);
  return { accessToken, refreshToken };
};

// Регистрация
exports.register = async (req, res) => {
  try {
    const { email, password } = req.body;
    validatePassword(password);

    const [existing] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ message: 'Пользователь уже существует' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    await pool.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword]);

    logger.info(`User registered: ${email}`);
    res.status(201).json({ message: 'Пользователь успешно зарегистрирован' });

  } catch (e) {
    logger.error(`Registration error: ${e.message}`);
    res.status(500).json({ message: e.message || 'Ошибка сервера' });
  }
};

// Авторизация с установкой кук
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

    if (users.length === 0) throw new Error('Неверный email или пароль');
    
    const isMatch = await bcrypt.compare(password, users[0].password);
    if (!isMatch) throw new Error('Неверный email или пароль');

    const tokens = generateTokens(users[0].id);
    
    // Установка защищенных кук
    res.cookie('accessToken', tokens.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      maxAge: 15 * 60 * 1000 // 15 минут
    });

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'Strict',
      path: '/api/auth/refresh',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 дней
    });

    logger.info(`User logged in: ${email}`);
    res.status(200).json({ message: 'Успешная авторизация' });

  } catch (e) {
    logger.error(`Login error: ${e.message}`);
    res.status(500).json({ message: e.message || 'Ошибка сервера' });
  }
};

// Обновление токенов
exports.refresh = (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken || !refreshTokens.has(refreshToken)) {
      throw new Error('Invalid refresh token');
    }

    jwt.verify(refreshToken, process.env.REFRESH_SECRET, (err, decoded) => {
      if (err || Date.now() >= decoded.exp * 1000) {
        refreshTokens.delete(refreshToken);
        throw new Error('Refresh token expired');
      }
      
      const newTokens = generateTokens(decoded.userId);
      refreshTokens.delete(refreshToken);

      // Обновление кук
      res.cookie('accessToken', newTokens.accessToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'Strict',
        maxAge: 15 * 60 * 1000 
      });

      res.json({ accessToken: newTokens.accessToken });
    });
  } catch (e) {
    logger.error(`Refresh error: ${e.message}`);
    res.status(403).json({ message: e.message });
  }
};

// Выход
exports.logout = (req, res) => {
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  res.status(200).json({ message: 'Успешный выход' });
};

// Middleware аутентификации через куки
exports.authMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies.accessToken;
    if (!token) throw new Error('Токен отсутствует');

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [decoded.userId]);
    
    if (!users.length) throw new Error('Пользователь не найден');
    req.user = users[0];
    next();
  } catch (e) {
    logger.error(`Auth error: ${e.message}`);
    res.status(401).json({ message: 'Ошибка авторизации' });
  }
};