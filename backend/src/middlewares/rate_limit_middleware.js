import express from 'express';
import authController from '../controllers/auth_controllers.js';
import validate from '../middlewares/auth_validate.js';
import authMiddleware from '../middlewares/auth_middleware.js';
import { forgotPasswordLimiter, resetPasswordLimiter } from '../middlewares/rate_limit_middleware.js';
import {
  registerSchema,
  loginSchema,
  googleLoginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from '../validators/auth_validator.js';

const router = express.Router();

router.post('/register', validate(registerSchema), authController.register);
router.post('/login', validate(loginSchema), authController.login);
router.post('/google', validate(googleLoginSchema), authController.googleLogin);
router.post('/forgot-password', forgotPasswordLimiter, validate(forgotPasswordSchema), authController.forgotPasswor);
router.post('/reset-password', resetPasswordLimiter, validate(resetPasswordSchema), authController.resetPassword);

router.get('/me', authMiddleware, (req, res) => {
  return res.json({
    message: 'acesso autorizado.',
    userId: req.userId,
    role: req.userRole,
    email: req.userEmail,
  });
});

export default router;