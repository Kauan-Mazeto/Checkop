import prisma from './prisma.js';

/**
 * Registra uma tentativa de login (sucesso ou falha) para fins de auditoria
 * de segurança (RNF-23). Nunca lança erro para fora - uma falha ao gravar o
 * log não pode derrubar o fluxo de autenticação em si.
 */
export const logLoginAttempt = async ({ email, success, ip, userAgent, userId = null }) => {
  try {
    await prisma.loginAttempt.create({
      data: {
        email,
        success,
        ipAddress: ip,
        userAgent: userAgent || null,
        userId,
      },
    });
  } catch (err) {
    console.error('Erro ao gravar log de tentativa de login:', err);
  }
};