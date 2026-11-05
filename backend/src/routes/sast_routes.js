import express from 'express';
import sastController from '../controllers/sast_controllers.js';
import authMiddleware from '../middlewares/auth_middleware.js';

const router = express.Router();

router.use(authMiddleware);
router.post('/analyze', sastController.analyzeCode);

export default router;