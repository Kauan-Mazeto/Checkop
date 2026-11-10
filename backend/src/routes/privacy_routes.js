import express from 'express';
import { PRIVACY_POLICY } from '../lib/privacity.js';
import { TERMS_OF_USE } from '../lib/terms_of_use.js';

const router = express.Router();

// páginas públicas: precisam abrir antes do cadastro/login
router.get('/privacy-policy', (req, res) => {
  return res.status(200).json(PRIVACY_POLICY);
});

router.get('/terms-of-use', (req, res) => {
  return res.status(200).json(TERMS_OF_USE);
});

export default router;
