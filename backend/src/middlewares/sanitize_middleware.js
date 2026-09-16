// Reimplementação de express-mongo-sanitize compatível com Express 5.
//
// A lib original (express-mongo-sanitize@2.2.0) faz `req[key] = target`
// para body/params/headers/query. Isso quebra no Express 5 porque
// `req.query` (e `req.headers`) passaram a ser apenas getters no
// IncomingMessage — tentar reatribuir gera:
//   TypeError: Cannot set property query of #<IncomingMessage> which has
//   only a getter
// e derruba a requisição inteira com 500 antes mesmo de chegar no
// controller (foi isso que quebrou POST /api/auth/register).
//
// Aqui, em vez de reatribuir req.query, mutamos o objeto em memória —
// deletando chaves perigosas (que começam com "$" ou contêm ".", usadas
// em operadores de injeção NoSQL) direto nas propriedades existentes.
// Isso funciona em qualquer versão do Express porque nunca fazemos
// `req.query = algo`, só `delete req.query[chave]`.

const isPlainObject = (value) => value !== null && typeof value === 'object';

const sanitizeInPlace = (value) => {
  if (!isPlainObject(value)) {
    return;
  }

  for (const key of Object.keys(value)) {
    if (key.startsWith('$') || key.includes('.')) {
      delete value[key];
      continue;
    }

    sanitizeInPlace(value[key]);
  }
};

const sanitizeMiddleware = (req, res, next) => {
  sanitizeInPlace(req.body);
  sanitizeInPlace(req.params);

  // req.query no Express 5 é um getter que reparseia req.url a cada
  // leitura (não é armazenado em nenhuma propriedade comum) — então só
  // mutar o objeto retornado não é suficiente, a próxima leitura de
  // req.query volta a computar do zero e "desfaz" a sanitização. Por
  // isso: lemos uma vez, sanitizamos essa cópia, e substituímos o
  // getter por uma propriedade de dado comum nesta instância de req
  // (configurable: true no getter original do Express permite isso).
  const sanitizedQuery = req.query;
  sanitizeInPlace(sanitizedQuery);

  Object.defineProperty(req, 'query', {
    value: sanitizedQuery,
    writable: true,
    configurable: true,
    enumerable: true,
  });

  next();
};

export default sanitizeMiddleware;