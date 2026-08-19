import { verifyToken } from '../constants/utils.js';
import prisma from '../lib/prisma.js';

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });
    }

    const parts = authHeader.split(' ');

    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return res.status(401).json({ error: 'Formato do token inválido. Use: Bearer <TOKEN>' });
    }

    const token = parts[1];
    const decoded = await verifyToken(token);

    const userExists = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, role: true, email: true },
    });

    if (!userExists) {
      return res.status(401).json({ error: 'Utilizador associado ao token não existe mais.' });
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