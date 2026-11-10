import express from 'express';
import sastController from '../controllers/sast_controllers.js';
import authMiddleware from '../middlewares/auth_middleware.js';
import { sastLimiter } from '../middlewares/rate_limit_middleware.js';
import { requirePlan } from '../middlewares/plan_middleware.js';

const router = express.Router();

router.use(authMiddleware);
router.post('/analyze', requirePlan('PREMIUM'), sastLimiter, sastController.analyzeCode);

export default router;