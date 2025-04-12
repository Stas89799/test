const pool = require('../db/connection');

(async () => {
  try {
    const [rows] = await pool.query('SELECT 1 + 1 AS result');
    console.log('Подключение успешно! Результат:', rows[0].result);
    process.exit(0);
  } catch (err) {
    console.error('Ошибка подключения:', err.message);
    process.exit(1);
  }
})();