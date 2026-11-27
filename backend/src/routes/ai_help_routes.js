import express from 'express';
import aiHelpController from '../controllers/ai_help_controllers.js';
import authMiddleware from '../middlewares/auth_middleware.js';
import validate from '../middlewares/auth_validate.js';
import { aiFixLimiter } from '../middlewares/rate_limit_middleware.js';
import { requirePlan } from '../middlewares/plan_middleware.js';
import { aiChatSchema } from '../validators/ai_help_validator.js';

// Ajuda por IA (Premium + créditos de IA). Política de Privacidade, item 2.5.
const router = express.Router();

router.use(authMiddleware, requirePlan('PREMIUM'));
router.get('/sources', aiHelpController.listSources);
router.get('/context', aiHelpController.previewContext);
router.post('/chat', aiFixLimiter, validate(aiChatSchema), aiHelpController.chat);

export default router;
