import express from 'express';
import authController from '../controllers/auth_controllers.js';
import validate from '../middlewares/auth_validate.js';
import authMiddleware from '../middlewares/auth_middleware.js';
import {
  forgotPasswordLimiter,
  resetPasswordLimiter,
  loginLimiter,
  registerLimiter,
} from '../middlewares/rate_limit_middleware.js';
import {
  registerSchema,
  loginSchema,
  googleLoginSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from '../validators/auth_validator.js';

const router = express.Router();

router.post('/register', registerLimiter, validate(registerSchema), authController.register);
router.post('/login', loginLimiter, validate(loginSchema), authController.login);
router.post('/google', validate(googleLoginSchema), authController.googleLogin);
router.post('/forgot-password', forgotPasswordLimiter, validate(forgotPasswordSchema), authController.forgotPassword);
router.post('/reset-password', resetPasswordLimiter, validate(resetPasswordSchema), authController.resetPassword);
router.post('/logout', authMiddleware, authController.logout);
router.delete('/account', authMiddleware, authController.deleteAccount);
router.get('/login-history', authMiddleware, authController.getLoginHistory);

router.get('/me', authMiddleware, (req, res) => {
  return res.json({
    message: 'acesso autorizado.',
    userId: req.userId,
    role: req.userRole,
    email: req.userEmail,
  });
});

export default router;