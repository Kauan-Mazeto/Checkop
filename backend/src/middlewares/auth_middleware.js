import { verifyToken } from '../constants/utils.js';
import prisma from '../lib/prisma.js';
import { latestTermsAcceptance, termsStatus, termsUpdateRequiredBody } from '../lib/terms_status.js';

// Com os Termos desatualizados, o usuário ainda pode cuidar da conta: ver a
// sessão, aceitar a nova versão, baixar os dados, excluir a conta e sair
// (direitos da LGPD não dependem de aceitar os Termos novos). Usar a
// plataforma (alvos, varreduras, análise de código) exige o novo aceite.
const ROUTES_ALLOWED_WITH_OUTDATED_TERMS = ['/api/auth', '/api/privacy'];

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies?.token;

    if (!token) {
      return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });
    }

    const decoded = await verifyToken(token);

    const userExists = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, name: true, role: true, plan: true, email: true, tokenVersion: true, notifyScanEmail: true, language: true },
    });

    if (!userExists) {
      return res.status(401).json({ error: 'Token inválido ou expirado.' });
    }

    // se a versão do token não bate com a versão vigente do usuário, o token
    // foi emitido antes do último logout/redefinição de senha - trata como
    // inválido, mesma mensagem genérica de sempre (não revela o motivo exato)
    if (decoded.tokenVersion !== userExists.tokenVersion) {
      return res.status(401).json({ error: 'Token inválido ou expirado.' });
    }

    req.userId = userExists.id;
    req.userRole = userExists.role;
    req.userEmail = userExists.email;
    req.userName = userExists.name;
    req.userPlan = userExists.plan;
    req.userNotifyScanEmail = userExists.notifyScanEmail;
    req.userLanguage = userExists.language;
    req.termsStatus = termsStatus(await latestTermsAcceptance(userExists.id));

    if (req.termsStatus.updateRequired && !ROUTES_ALLOWED_WITH_OUTDATED_TERMS.includes(req.baseUrl)) {
      return res.status(403).json(termsUpdateRequiredBody());
    }

    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
};

export default authMiddleware;