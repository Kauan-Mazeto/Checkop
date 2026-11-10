import prisma from './prisma.js';

// Marco Civil (art. 15) obriga a guardar registros de acesso por 6 meses; a LGPD
// (art. 6º, III, e art. 16) manda eliminar quando a finalidade acaba. Por isso
// os registros são apagados assim que passam do prazo.
export const RETENTION_MONTHS = 6;
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

export const retentionCutoff = (now = new Date()) => {
  const cutoff = new Date(now);
  cutoff.setMonth(cutoff.getMonth() - RETENTION_MONTHS);
  return cutoff;
};

export const purgeExpiredRecords = async (now = new Date()) => {
  const where = { createdAt: { lt: retentionCutoff(now) } };
  const [audit, logins] = await prisma.$transaction([
    prisma.auditLog.deleteMany({ where }),
    prisma.loginAttempt.deleteMany({ where }),
  ]);
  return { auditLogs: audit.count, loginAttempts: logins.count };
};

export const scheduleRetentionPurge = () => {
  const run = () =>
    purgeExpiredRecords().catch((err) => console.error('Falha na limpeza de registros expirados:', err));
  run();
  // unref: o timer não impede o processo de encerrar (SIGTERM)
  setInterval(run, ONE_DAY_MS).unref();
};
