import express from 'express';
import authMiddleware from '../middlewares/auth_middleware.js';
import { logAudit, AUDIT_ACTIONS } from '../lib/audit_log.js';
import { runTemplateUpdate, templateUpdateStatus } from '../lib/template_updates.js';

const router = express.Router();

// só administradores (perfil ADM)
export const requireAdmin = (req, res, next) =>
  req.userRole === 'ADM' ? next() : res.status(403).json({ error: 'Acesso restrito a administradores.' });

router.use(authMiddleware, requireAdmin);

// RF-45: status e disparo manual da atualização dos templates do Nuclei
router.get('/templates', (req, res) => res.status(200).json(templateUpdateStatus()));

router.post('/templates/update', async (req, res) => {
  const result = await runTemplateUpdate();
  await logAudit(req, {
    action: AUDIT_ACTIONS.TEMPLATES_UPDATED,
    resourceType: 'system',
    details: { ok: !result.lastError, error: result.lastError },
  });
  if (!result.started) return res.status(409).json({ error: 'Já existe uma atualização em andamento.', ...result });
  if (result.lastError) return res.status(502).json({ error: result.lastError, ...result });
  return res.status(200).json({ message: 'Templates do Nuclei atualizados.', ...result });
});

export default router;
