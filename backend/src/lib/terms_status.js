import prisma from './prisma.js';
import { TERMS_OF_USE } from './terms_of_use.js';

// Aceite dos Termos de Uso. Cada versão aceita vira um registro (histórico,
// com data, IP e navegador); o mais recente diz se o usuário está em dia.
// Subir TERMS_OF_USE.version faz todo mundo aceitar de novo no próximo acesso
// (Termos, seção 14: alteração relevante pode exigir novo aceite).

export const TERMS_UPDATE_REQUIRED = 'TERMS_UPDATE_REQUIRED';

export const latestTermsAcceptance = (userId) =>
  prisma.termsAcceptance.findFirst({
    where: { userId },
    orderBy: { acceptedAt: 'desc' },
    select: { version: true, acceptedAt: true },
  });

/** Situação do usuário frente à versão atual. Sem aceite nenhum também precisa aceitar. */
export const termsStatus = (latest) => ({
  currentVersion: TERMS_OF_USE.version,
  lastUpdated: TERMS_OF_USE.lastUpdated,
  acceptedVersion: latest?.version ?? null,
  acceptedAt: latest?.acceptedAt ?? null,
  updateRequired: latest?.version !== TERMS_OF_USE.version,
});

export const recordTermsAcceptance = (userId, req) =>
  prisma.termsAcceptance.create({
    data: {
      userId,
      version: TERMS_OF_USE.version,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || null,
    },
  });

export const termsUpdateRequiredBody = () => ({
  error: `Os Termos de Uso foram atualizados (versão ${TERMS_OF_USE.version}). Leia e aceite a nova versão para continuar.`,
  code: TERMS_UPDATE_REQUIRED,
  currentVersion: TERMS_OF_USE.version,
});
