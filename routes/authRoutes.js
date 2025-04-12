const express = require('express');
const authController = require('../controllers/authController');
const { authenticate } = require('../middlewares/authMiddleware');

const router = express.Router();

// Маршрут для регистрации
router.post('/register', authController.register);

// Маршрут для авторизации
router.post('/login', authController.login);

// Маршрут для обновления токенов
router.post('/refresh', authController.refresh);

// Маршрут для выхода из системы
router.post('/logout', authenticate, authController.logout);

// Middleware аутентификации
router.use(authController.authMiddleware);

module.exports = router;