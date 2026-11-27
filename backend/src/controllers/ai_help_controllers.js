import prisma from '../lib/prisma.js';
import { AiError, aiProviderLabel, isAiEnabled } from '../lib/ai_provider.js';
import { AI_CHAT_COST, answerQuestion, loadContext } from '../lib/ai_help.js';
import { AI_CREDITS_REQUIRED_CODE } from '../constants/ai_credits.js';
import { contextQuerySchema } from '../validators/ai_help_validator.js';
import { logAudit, AUDIT_ACTIONS } from '../lib/audit_log.js';

const AI_ERROR_STATUS = { AI_NOT_CONFIGURED: 503, AI_BUSY: 429, AI_REFUSED: 422, AI_FIX_FAILED: 502 };

const fileNamesOf = (json) => {
  try {
    return JSON.parse(json).map((f) => f.name);
  } catch {
    return [];
  }
};

// Itens que dá para escolher: varreduras concluídas e análises do histórico.
const listSources = async (req, res) => {
  try {
    const [user, scans, analyses] = await Promise.all([
      prisma.user.findUnique({ where: { id: req.userId }, select: { aiCredits: true } }),
      prisma.scan.findMany({
        where: { userId: req.userId, status: { in: ['COMPLETED', 'CANCELED'] } },
        orderBy: { createdAt: 'desc' },
        take: 30,
        select: { id: true, targetUrl: true, objective: true, createdAt: true, _count: { select: { findings: true } } },
      }),
      prisma.codeAnalysis.findMany({
        where: { userId: req.userId },
        orderBy: { createdAt: 'desc' },
        take: 30,
        select: { id: true, files: true, findingsCount: true, createdAt: true },
      }),
    ]);
    return res.status(200).json({
      enabled: isAiEnabled(),
      // quem recebe a pergunta e o resumo (mostrado na tela antes do envio)
      provider: aiProviderLabel(),
      credits: user?.aiCredits ?? 0,
      cost: AI_CHAT_COST,
      scans: scans.map((s) => ({
        id: s.id, targetUrl: s.targetUrl, objective: s.objective, createdAt: s.createdAt, findingsCount: s._count.findings,
      })),
      analyses: analyses.map((a) => ({ id: a.id, files: fileNamesOf(a.files), findingsCount: a.findingsCount, createdAt: a.createdAt })),
    });
  } catch (error) {
    console.error('Erro ao listar itens da Ajuda por IA:', error);
    return res.status(500).json({ error: 'Erro interno ao carregar suas varreduras e análises.' });
  }
};

// Prévia: o texto exato que vai para o provedor de IA junto com a pergunta.
const previewContext = async (req, res) => {
  const parsed = contextQuerySchema.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: 'Escolha uma varredura ou análise válida.' });
  try {
    const context = await loadContext({ userId: req.userId, ...parsed.data });
    if (!context) return res.status(404).json({ error: 'Varredura ou análise não encontrada.' });
    return res.status(200).json(context);
  } catch (error) {
    console.error('Erro ao montar a prévia da Ajuda por IA:', error);
    return res.status(500).json({ error: 'Erro interno ao montar a prévia.' });
  }
};

// Uma pergunta = AI_CHAT_COST crédito, debitado antes (atômico) e devolvido se a IA falhar.
const chat = async (req, res) => {
  if (!isAiEnabled()) {
    return res.status(503).json({ error: 'A Ajuda por IA não está configurada neste servidor.', code: 'AI_NOT_CONFIGURED' });
  }
  const { kind, id, messages } = req.body;

  let context;
  let role;
  try {
    context = await loadContext({ userId: req.userId, kind, id });
    role = (await prisma.user.findUnique({ where: { id: req.userId }, select: { role: true } }))?.role;
  } catch (error) {
    console.error('Erro ao montar o contexto da Ajuda por IA:', error);
    return res.status(500).json({ error: 'Erro interno ao preparar a pergunta.' });
  }
  if (!context) return res.status(404).json({ error: 'Varredura ou análise não encontrada.' });

  const debit = await prisma.user.updateMany({
    where: { id: req.userId, aiCredits: { gte: AI_CHAT_COST } },
    data: { aiCredits: { decrement: AI_CHAT_COST } },
  });
  if (debit.count === 0) {
    return res.status(402).json({
      error: 'Cada pergunta na Ajuda por IA usa 1 crédito de IA, vendido à parte do plano. Compre um pacote para continuar.',
      code: AI_CREDITS_REQUIRED_CODE,
    });
  }

  try {
    const result = await answerQuestion({ context, messages, role });
    const user = await prisma.user.findUnique({ where: { id: req.userId }, select: { aiCredits: true } });
    // só metadados: a pergunta e a resposta não vão para o log
    await logAudit(req, {
      action: AUDIT_ACTIONS.AI_HELP_ASKED,
      resourceType: kind === 'scan' ? 'scan' : 'code_analysis',
      resourceId: id,
      details: { credits: AI_CHAT_COST, turn: Math.ceil(messages.length / 2) },
    });
    return res.status(200).json({ ...result, credits: user?.aiCredits ?? 0 });
  } catch (error) {
    await prisma.user
      .update({ where: { id: req.userId }, data: { aiCredits: { increment: AI_CHAT_COST } } })
      .catch((refundError) => console.error('[ai_help] não foi possível devolver o crédito:', refundError));
    if (error instanceof AiError) {
      return res.status(AI_ERROR_STATUS[error.code] ?? 502).json({ error: error.message, code: error.code, refunded: true });
    }
    console.error('Erro na Ajuda por IA:', error);
    return res.status(500).json({ error: 'Erro interno na Ajuda por IA. O crédito foi devolvido.', refunded: true });
  }
};

export default { listSources, previewContext, chat };
