import express from 'express';
import sastController from '../controllers/sast_controllers.js';
import authMiddleware from '../middlewares/auth_middleware.js';
import validate from '../middlewares/auth_validate.js';
import { sastLimiter, aiFixLimiter } from '../middlewares/rate_limit_middleware.js';
import { requirePlan } from '../middlewares/plan_middleware.js';
import { aiFixSchema } from '../validators/sast_validator.js';

const router = express.Router();

router.use(authMiddleware);
router.post('/analyze', requirePlan('PREMIUM'), sastLimiter, sastController.analyzeCode);
router.get('/ai-config', sastController.getAiConfig);
router.post('/fix', requirePlan('PREMIUM'), aiFixLimiter, validate(aiFixSchema), sastController.fixWithAi);

export default router;
