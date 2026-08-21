import prisma from '../lib/prisma.js';

 
 // @param {string} model - nome do model no Prisma (ex: 'scan', 'finding')
 // @param {string} idParam - nome do parâmetro de rota com o id (padrão: 'id')

export const requireOwnership = (model, idParam = 'id') => async (req, res, next) => {
  try {
    const resourceId = req.params[idParam];

    const record = await prisma[model].findUnique({
      where: { id: resourceId },
    });

    if (!record || record.userId !== req.userId) {
      return res.status(404).json({ error: 'Recurso não encontrado.' });
    }

    req.resource = record;
    return next();
  } catch (error) {
    console.error('Erro ao verificar posse do recurso:', error);
    return res.status(500).json({ error: 'Erro interno ao verificar acesso ao recurso.' });
  }
};