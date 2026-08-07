// src/routes/authRoutes.js
const express = require('express');
const router = express.Router();

const authController = require('../controllers/authController');
const validate = require('../middlewares/validateMiddleware');
const authMiddleware = require('../middlewares/authMiddleware');

const { registerSchema, loginSchema } = require('../validators/authValidator');

router.post('/register', validate(registerSchema), authController.register);

router.post('/login', validate(loginSchema), authController.login);

router.get('/me', authMiddleware, (req, res) => {
  return res.json({
    message: 'Acesso autorizado no Checkop!',
    userId: req.userId,
    role: req.userRole,
    email: req.userEmail,
  });
});

module.exports = router;