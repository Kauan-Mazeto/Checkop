import express from 'express';
import scanController from '../controllers/scan_controllers.js';
import validate from '../middlewares/auth_validate.js';
import authMiddleware from '../middlewares/auth_middleware.js';
import { requireOwnership } from '../middlewares/ownership_middleware.js';
import { scanCreationLimiter } from '../middlewares/rate_limit_middleware.js';
import { createScanSchema } from '../validators/scan_validator.js';

const router = express.Router();

router.use(authMiddleware);

router.post('/', scanCreationLimiter, validate(createScanSchema), scanController.createScan);
router.get('/', scanController.listScans);
router.get('/suspicious', scanController.listSuspiciousScans);
router.get('/:id', requireOwnership('scan'), scanController.getScanById);

export default router;