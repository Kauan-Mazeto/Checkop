import express from 'express';
import { PRIVACY_POLICY } from '../lib/privacity.js';

const router = express.Router();

router.get('/privacy-policy', (req, res) => {
  return res.status(200).json(PRIVACY_POLICY);
});

export default router;