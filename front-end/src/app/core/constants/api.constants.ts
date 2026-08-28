// URL base da API do backend Checkop (Express, ver backend/src/server.js).
// O backend expõe as rotas de auth sob /api/auth (ver backend/src/routes/auth_routes.js)
// e roda por padrão na porta 3000 (ver process.env.PORT || 3000 em server.js).
// TODO: mover para providers de environment do Angular quando o projeto tiver
// builds de homologação/produção com URLs diferentes.
export const API_BASE_URL = 'http://localhost:3000/api';