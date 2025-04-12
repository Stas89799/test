const express = require('express');
const profileController = require('../controllers/profileController');
const { authenticate } = require('../middlewares/authMiddleware');

const router = express.Router();

// Маршрут для сохранения данных профиля
router.post('/save', authenticate, profileController.saveProfile);

module.exports = router;