const db = require('../db/connection');

exports.saveProfile = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      phone,
      email,
      company,
      address,
      instagram,
      facebook
    } = req.body;

    await db.execute(
      `UPDATE users SET 
        first_name = ?,
        last_name = ?,
        phone = ?,
        company = ?,
        address = ?,
        instagram = ?,
        facebook = ?
      WHERE email = ?`,
      [firstName, lastName, phone, company, address, instagram, facebook, email]
    );

    res.json({ success: true, message: 'Profile updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};