import express from 'express';
import scanController from '../controllers/scan_controllers.js';
import validate from '../middlewares/auth_validate.js';
import authMiddleware from '../middlewares/auth_middleware.js';
import { requireOwnership } from '../middlewares/ownership_middleware.js';
import { scanCreationLimiter } from '../middlewares/rate_limit_middleware.js';
import { createScanSchema, runScanAuthSchema} from '../validators/scan_validator.js';


const router = express.Router();

router.use(authMiddleware);

router.post('/', scanCreationLimiter, validate(createScanSchema), scanController.createScan);
router.get('/', scanController.listScans);
router.get('/suspicious', scanController.listSuspiciousScans);
router.get('/stats', scanController.getScanStats);
router.get('/export', scanController.exportScans);
router.get('/objectives', scanController.getObjectives);
router.get('/:id', requireOwnership('scan'), scanController.getScanById);
router.get('/:id/compare', requireOwnership('scan'), scanController.compareScans);
router.post('/:id/run', scanCreationLimiter, requireOwnership('scan'), validate(runScanAuthSchema), scanController.runScan);
router.post('/:id/cancel', requireOwnership('scan'), scanController.cancelScan);

export default router;