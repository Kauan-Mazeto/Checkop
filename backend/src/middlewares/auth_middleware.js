import { verifyToken } from '../constants/utils.js';
import prisma from '../lib/prisma.js';

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies?.token;

    if (!token) {
      return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });
    }

    const decoded = await verifyToken(token);

    const userExists = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, role: true, email: true, tokenVersion: true },
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

    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
};

export default authMiddleware;