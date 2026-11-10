import prisma from '../lib/prisma.js';
import { detectEnvironment, ScanValidationError } from '../lib/environment_detector.js';
import { logAudit, AUDIT_ACTIONS } from '../lib/audit_log.js';
import { refreshTargetVerification } from '../lib/target_ownership.js';
import {
  buildInstructions,
  generateVerificationToken,
  resolveTargetHostname,
  SCOPE_BY_METHOD,
  TargetVerificationError,
} from '../lib/target_verification.js';

const MAX_TARGETS_PER_USER = 20;

const serializeTarget = (target) => ({
  id: target.id,
  hostname: target.hostname,
  scope: target.scope,
  verificationMethod: target.verificationMethod,
  verified: Boolean(target.verifiedAt),
  verifiedAt: target.verifiedAt,
  lastCheckedAt: target.lastCheckedAt,
  createdAt: target.createdAt,
  instructions: buildInstructions(target),
});

const createTarget = async (req, res) => {
  try {
    const { url, method } = req.body;

    let detection;
    try {
      detection = await detectEnvironment(url);
    } catch (err) {
      if (err instanceof ScanValidationError) return res.status(400).json({ error: err.message });
      throw err;
    }

    if (detection.suspicious) {
      return res.status(400).json({ error: 'Este domínio público resolve para rede interna e não pode ser cadastrado.' });
    }
    if (detection.environment === 'DEVELOPMENT') {
      return res.status(400).json({
        error: 'Alvos locais (localhost ou rede privada) não precisam de verificação. Crie a varredura direto.',
      });
    }

    let hostname;
    try {
      hostname = resolveTargetHostname(url, method);
    } catch (err) {
      if (err instanceof TargetVerificationError) return res.status(400).json({ error: err.message });
      throw err;
    }
    const scope = SCOPE_BY_METHOD[method];

    const existing = await prisma.target.findUnique({
      where: { userId_hostname_scope: { userId: req.userId, hostname, scope } },
    });
    if (existing) {
      return res.status(409).json({ error: 'Este alvo já está cadastrado.', target: serializeTarget(existing) });
    }

    const count = await prisma.target.count({ where: { userId: req.userId } });
    if (count >= MAX_TARGETS_PER_USER) {
      return res.status(400).json({ error: `Limite de ${MAX_TARGETS_PER_USER} alvos por conta atingido.` });
    }

    const target = await prisma.target.create({
      data: {
        userId: req.userId,
        hostname,
        scope,
        verificationMethod: method,
        verificationToken: generateVerificationToken(),
      },
    });

    await logAudit(req, {
      action: AUDIT_ACTIONS.TARGET_CREATED,
      resourceType: 'target',
      resourceId: target.id,
      details: { hostname, scope, method },
    });

    return res.status(201).json({
      message: 'Alvo cadastrado. Publique a prova de controle e depois chame a verificação.',
      target: serializeTarget(target),
    });
  } catch (error) {
    console.error('Erro ao cadastrar alvo:', error);
    return res.status(500).json({ error: 'Erro interno ao cadastrar alvo.' });
  }
};

const listTargets = async (req, res) => {
  try {
    const targets = await prisma.target.findMany({
      where: { userId: req.userId },
      orderBy: { createdAt: 'desc' },
    });
    return res.status(200).json({ targets: targets.map(serializeTarget) });
  } catch (error) {
    console.error('Erro ao listar alvos:', error);
    return res.status(500).json({ error: 'Erro interno ao listar alvos.' });
  }
};

const getTargetById = async (req, res) => res.status(200).json({ target: serializeTarget(req.resource) });

const verifyTarget = async (req, res) => {
  try {
    const target = req.resource;
    const isOwner = await refreshTargetVerification(target);

    await logAudit(req, {
      action: isOwner ? AUDIT_ACTIONS.TARGET_VERIFIED : AUDIT_ACTIONS.TARGET_VERIFICATION_FAILED,
      resourceType: 'target',
      resourceId: target.id,
      details: { hostname: target.hostname, method: target.verificationMethod },
    });

    const updated = await prisma.target.findUnique({ where: { id: target.id } });

    if (!isOwner) {
      return res.status(422).json({
        error: 'Não encontramos a prova de controle publicada. Confira as instruções e tente de novo.',
        code: 'VERIFICATION_NOT_FOUND',
        target: serializeTarget(updated),
      });
    }

    return res.status(200).json({ message: 'Alvo verificado com sucesso.', target: serializeTarget(updated) });
  } catch (error) {
    console.error('Erro ao verificar alvo:', error);
    return res.status(500).json({ error: 'Erro interno ao verificar alvo.' });
  }
};

const deleteTarget = async (req, res) => {
  try {
    const target = req.resource;
    await prisma.target.delete({ where: { id: target.id } });

    await logAudit(req, {
      action: AUDIT_ACTIONS.TARGET_DELETED,
      resourceType: 'target',
      resourceId: target.id,
      details: { hostname: target.hostname },
    });

    return res.status(200).json({ message: 'Alvo removido.' });
  } catch (error) {
    console.error('Erro ao remover alvo:', error);
    return res.status(500).json({ error: 'Erro interno ao remover alvo.' });
  }
};

export default { createTarget, listTargets, getTargetById, verifyTarget, deleteTarget };
