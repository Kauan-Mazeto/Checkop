import prisma from './prisma.js';
import { checkTargetOwnership, targetCoversHost, TargetVerificationError } from './target_verification.js';

/** Primeiro alvo verificado do usuário que cobre o host da URL (ou null). */
export const findVerifiedTargetForUrl = async (userId, url) => {
  const { hostname } = new URL(url);
  const targets = await prisma.target.findMany({
    where: { userId, verifiedAt: { not: null } },
    orderBy: { verifiedAt: 'asc' },
  });
  return targets.find((target) => targetCoversHost(target, hostname)) ?? null;
};

/**
 * Confere de novo a prova de controle e grava o resultado. Quem removeu o TXT,
 * o arquivo ou a tag (ou perdeu o domínio) perde a verificação na hora.
 * @returns {Promise<boolean>} true se o alvo continua verificado
 */
export const refreshTargetVerification = async (target) => {
  let isOwner;
  try {
    isOwner = await checkTargetOwnership(target);
  } catch (err) {
    if (!(err instanceof TargetVerificationError)) throw err;
    isOwner = false;
  }

  const now = new Date();
  await prisma.target.update({
    where: { id: target.id },
    data: {
      lastCheckedAt: now,
      verifiedAt: isOwner ? (target.verifiedAt ?? now) : null,
    },
  });
  return isOwner;
};
