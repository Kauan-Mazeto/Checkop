import { OAuth2Client } from 'google-auth-library';

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Verifica o id_token enviado pelo frontend, vai lançar erro se inválido, expirado
// ou emitido para um client id diferente do configurado.
export const verifyGoogleToken = async (idToken) => {
  const ticket = await client.verifyIdToken({
    idToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });
  return ticket.getPayload(); // retorna o payload do google p/ login
};

// Ajustar erro que retorna password incorreto no login.

export default client;