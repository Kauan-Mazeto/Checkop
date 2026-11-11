import prisma from './prisma.js';

/**
 * Registra uma tentativa de login (sucesso ou falha) para fins de auditoria;
 * de segurança (RNF-23). Caso ocorra erro, nunca o retorna diretamente;
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

// Ações registradas em AuditLog (RF-16). Strings fixas para dar para filtrar depois.
export const AUDIT_ACTIONS = Object.freeze({
  TARGET_CREATED: 'TARGET_CREATED',
  TARGET_VERIFIED: 'TARGET_VERIFIED',
  TARGET_VERIFICATION_FAILED: 'TARGET_VERIFICATION_FAILED',
  TARGET_DELETED: 'TARGET_DELETED',
  SCAN_CREATED: 'SCAN_CREATED',
  SCAN_BLOCKED: 'SCAN_BLOCKED',
  SCAN_STARTED: 'SCAN_STARTED',
  PLAN_CHANGED: 'PLAN_CHANGED',
});

/**
 * Registra uma ação para auditoria e para os registros de acesso exigidos pelo
 * Marco Civil (art. 15): quem, o quê, quando e de qual IP. Minimização (LGPD,
 * art. 6º, III): não grave e-mail, senha nem credenciais em `details`.
 * Igual ao logLoginAttempt, falha de log nunca derruba o fluxo principal.
 */
export const logAudit = async (req, { action, resourceType = null, resourceId = null, details = null }) => {
  try {
    await prisma.auditLog.create({
      data: {
        userId: req.userId ?? null,
        action,
        resourceType,
        resourceId,
        ipAddress: req.ip ?? null,
        userAgent: req.headers?.['user-agent'] || null,
        details: details ? JSON.stringify(details) : null,
      },
    });
  } catch (err) {
    console.error('Erro ao gravar log de auditoria:', err);
  }
};
