const validate = (schema) => async (req, res, next) => {
  try {
    const validatedData = await schema.parseAsync(req.body);
    req.body = validatedData;
    return next();
  } catch (error) {
    if (error.issues) {
      const formattedErrors = error.issues.map((err) => ({
        field: err.path[0],
        message: err.message,
      }));

      if (process.env.MODO_DEV === "DEV") {
        return res.status(400).json({
          error: 'Dados de entrada inválidos.',
          formattedErrors,
        });
      } else {
        return res.status(400).json({
          error: 'Dados de entrada inválidos.',
        });
      }
    }

    return res.status(500).json({ error: 'Erro interno ao validar dados de entrada.'})
  }}

export default validate;