// src/middlewares/validateMiddleware.js
const validate = (schema) => async (req, res, next) => {
  try {
    // parseAsync executa as validações assíncronas do Zod
    const validatedData = await schema.parseAsync(req.body);
    
    // Sobrescreve req.body com os dados higienizados e tipados
    req.body = validatedData;
    
    return next();
  } catch (error) {
    // Se for erro de validação do Zod
    if (error.issues) {
      const formattedErrors = error.issues.map((err) => ({
        field: err.path[0],
        message: err.message,
      }));

      return res.status(400).json({
        error: 'Dados de entrada inválidos.',
        details: formattedErrors,
      });
    }

    return res.status(500).json({ error: 'Erro interno ao validar dados de entrada.' });
  }
};

module.exports = validate;