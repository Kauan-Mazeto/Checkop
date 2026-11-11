import express from 'express';
import targetController from '../controllers/target_controllers.js';
import validate from '../middlewares/auth_validate.js';
import authMiddleware from '../middlewares/auth_middleware.js';
import { requireOwnership } from '../middlewares/ownership_middleware.js';
import { targetVerificationLimiter } from '../middlewares/rate_limit_middleware.js';
import { createTargetSchema } from '../validators/target_validator.js';

const router = express.Router();

router.use(authMiddleware);

router.post('/', validate(createTargetSchema), targetController.createTarget);
router.get('/', targetController.listTargets);
router.get('/:id', requireOwnership('target'), targetController.getTargetById);
router.post('/:id/verify', targetVerificationLimiter, requireOwnership('target'), targetController.verifyTarget);
router.delete('/:id', requireOwnership('target'), targetController.deleteTarget);

export default router;
