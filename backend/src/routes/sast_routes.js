import express from 'express';
import sastController from '../controllers/sast_controllers.js';
import authMiddleware from '../middlewares/auth_middleware.js';
import validate from '../middlewares/auth_validate.js';
import { sastLimiter, aiFixLimiter } from '../middlewares/rate_limit_middleware.js';
import { requirePlan } from '../middlewares/plan_middleware.js';
import { aiFixSchema, fullFixSchema, purchaseCreditsSchema } from '../validators/sast_validator.js';

const router = express.Router();

router.use(authMiddleware);
router.post('/analyze', requirePlan('PREMIUM'), sastLimiter, sastController.analyzeCode);
// histórico (só o resumo de cada análise, nunca o código)
router.get('/history', requirePlan('PREMIUM'), sastController.listHistory);
router.delete('/history', requirePlan('PREMIUM'), sastController.clearHistory);
router.delete('/history/:id', requirePlan('PREMIUM'), sastController.deleteHistoryItem);
router.get('/ai-config', sastController.getAiConfig);
router.post('/fix', requirePlan('PREMIUM'), aiFixLimiter, validate(aiFixSchema), sastController.fixWithAi);
// correção do arquivo inteiro: Premium + créditos de IA (pagos à parte)
router.post('/fix-file', requirePlan('PREMIUM'), aiFixLimiter, validate(fullFixSchema), sastController.fixFullFile);
router.post('/credits/purchase', requirePlan('PREMIUM'), validate(purchaseCreditsSchema), sastController.purchaseCredits);

export default router;
