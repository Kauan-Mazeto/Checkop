// src/middlewares/authMiddleware.js
const { verifyToken } = require('../utils/jwt');
const prisma = require('../lib/prisma');

module.exports = async (req, res, next) => {
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

    // Decodifica o Token JWT
    const decoded = await verifyToken(token);

    // Opcional: Confirmar se o utilizador ainda existe na base de dados SQLite
    const userExists = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, role: true, email: true }
    });

    if (!userExists) {
      return res.status(401).json({ error: 'Utilizador associado ao token não existe mais.' });
    }

    // Anexa as informações ao objeto de requisição
    req.userId = userExists.id;
    req.userRole = userExists.role;
    req.userEmail = userExists.email;

    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
};