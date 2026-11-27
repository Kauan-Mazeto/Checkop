import { runSastScan } from '../lib/py/sast_client.js';
import { AiFixError, fixWholeFile, isAiFixEnabled, suggestFix } from '../lib/ai_fix.js';
import { aiProviderLabel } from '../lib/ai_provider.js';
import { AI_CREDITS_REQUIRED_CODE, AI_CREDIT_PACKS, FULL_FIX_COST, findPack } from '../constants/ai_credits.js';
import prisma from '../lib/prisma.js';
import { logAudit, AUDIT_ACTIONS } from '../lib/audit_log.js';
import { HISTORY_LIMIT, summarizeAnalysis, toHistoryItem } from '../lib/code_analysis_history.js';

// Recebe { files: { "app.js": "conteúdo..." } } direto do usuário logado e devolve
// o resultado para o front montar o code diff. O código não é gravado; do resultado
// fica só o resumo no histórico (lib/code_analysis_history.js).
const analyzeCode = async (req, res) => {
    try {
        const { files } = req.body;
        // COMPLETE (padrão) = todas as regras de todas as ferramentas; ESSENTIAL = só bug, sintaxe e segurança
        const depth = req.body.depth === 'ESSENTIAL' ? 'ESSENTIAL' : 'COMPLETE';

        if (!files || typeof files !== 'object' || Object.keys(files).length === 0) {
            return res.status(400).json({ error: 'Envie ao menos um arquivo em "files".' });
        }

        const result = await runSastScan({ files, language: req.userLanguage, depth });

        // histórico: só o resumo (nomes, contagens, títulos e linhas), nunca o código.
        // Se gravar falhar, a análise continua valendo para quem pediu.
        let historyId = null;
        try {
            const saved = await prisma.codeAnalysis.create({
                data: summarizeAnalysis({ userId: req.userId, files, depth, result }),
                select: { id: true },
            });
            historyId = saved.id;
        } catch (historyError) {
            console.error('[sast] não foi possível salvar o histórico da análise:', historyError);
        }

        return res.status(200).json({ ...result, historyId });
    } catch (error) {
        console.error('Erro na análise SAST:', error);
        // B10: a mensagem do motor pode conter caminhos e stderr do Semgrep; fica só no log
        return res.status(502).json({ error: 'Erro ao executar a análise de código. Tente novamente mais tarde.' });
    }
};

// O front só mostra o botão "Gerar correção com IA" quando o servidor tem credencial.
const getAiConfig = async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.userId }, select: { aiCredits: true } });
    return res.status(200).json({
      enabled: isAiFixEnabled(),
      // quem recebe o código na correção com IA (Anthropic ou Google)
      provider: aiProviderLabel(),
      // correção do arquivo inteiro: paga à parte, com créditos
      credits: user?.aiCredits ?? 0,
      fullFixCost: FULL_FIX_COST,
      packs: AI_CREDIT_PACKS,
    });
  } catch (error) {
    console.error('Erro ao ler a configuração de IA:', error);
    return res.status(500).json({ error: 'Erro interno ao ler a configuração de IA.' });
  }
};

// Compra demonstrativa de créditos (o TCC não tem gateway de pagamento, como a troca de plano)
const purchaseCredits = async (req, res) => {
  try {
    const pack = findPack(req.body.packId);
    const user = await prisma.user.update({
      where: { id: req.userId },
      data: { aiCredits: { increment: pack.credits } },
      select: { aiCredits: true },
    });
    await logAudit(req, { action: AUDIT_ACTIONS.AI_CREDITS_PURCHASED, details: { packId: pack.id, credits: pack.credits } });
    return res.status(200).json({
      message: `${pack.credits} créditos adicionados.`,
      credits: user.aiCredits,
    });
  } catch (error) {
    console.error('Erro ao comprar créditos:', error);
    return res.status(500).json({ error: 'Erro interno ao adicionar créditos.' });
  }
};

// Corrige o arquivo inteiro com IA. O crédito é debitado ANTES da chamada, numa
// operação atômica (dois cliques não gastam o mesmo crédito), e devolvido se a IA falhar.
const fixFullFile = async (req, res) => {
  if (!isAiFixEnabled()) {
    return res.status(503).json({ error: 'A correção com IA não está configurada neste servidor.', code: 'AI_NOT_CONFIGURED' });
  }

  const debit = await prisma.user.updateMany({
    where: { id: req.userId, aiCredits: { gte: FULL_FIX_COST } },
    data: { aiCredits: { decrement: FULL_FIX_COST } },
  });
  if (debit.count === 0) {
    return res.status(402).json({
      error: 'A correção do arquivo inteiro usa créditos de IA, vendidos à parte do plano. Compre um pacote para continuar.',
      code: AI_CREDITS_REQUIRED_CODE,
    });
  }

  try {
    const result = await fixWholeFile(req.body);
    const user = await prisma.user.findUnique({ where: { id: req.userId }, select: { aiCredits: true } });
    // só metadados: o código do usuário não vai para o log de auditoria
    await logAudit(req, {
      action: AUDIT_ACTIONS.AI_FULL_FIX,
      details: { filename: req.body.filename, findings: req.body.findings.length, changes: result.changes.length },
    });
    return res.status(200).json({ ...result, credits: user?.aiCredits ?? 0 });
  } catch (error) {
    await prisma.user
      .update({ where: { id: req.userId }, data: { aiCredits: { increment: FULL_FIX_COST } } })
      .catch((refundError) => console.error('[ai_fix] não foi possível devolver o crédito:', refundError));
    if (error instanceof AiFixError) {
      return res.status(AI_ERROR_STATUS[error.code] ?? 502).json({ error: error.message, code: error.code, refunded: true });
    }
    console.error('Erro na correção completa com IA:', error);
    return res.status(500).json({ error: 'Erro interno na correção com IA. O crédito foi devolvido.', refunded: true });
  }
};

const AI_ERROR_STATUS = { AI_NOT_CONFIGURED: 503, AI_BUSY: 429, AI_REFUSED: 422, AI_FIX_FAILED: 502 };

// espec.txt 3.2 - correção sugerida pela IA para um achado da análise de código.
const fixWithAi = async (req, res) => {
    try {
        const fix = await suggestFix(req.body);
        return res.status(200).json(fix);
    } catch (error) {
        if (error instanceof AiFixError) {
            return res.status(AI_ERROR_STATUS[error.code] ?? 502).json({ error: error.message, code: error.code });
        }
        console.error('Erro ao gerar correção com IA:', error);
        return res.status(500).json({ error: 'Erro interno ao gerar a correção.' });
    }
};

// Histórico das análises (só resumo), da mais nova para a mais antiga.
const listHistory = async (req, res) => {
  try {
    const rows = await prisma.codeAnalysis.findMany({
      where: { userId: req.userId },
      orderBy: { createdAt: 'desc' },
      take: HISTORY_LIMIT,
    });
    return res.status(200).json({ analyses: rows.map(toHistoryItem), limit: HISTORY_LIMIT });
  } catch (error) {
    console.error('Erro ao listar o histórico da análise de código:', error);
    return res.status(500).json({ error: 'Erro interno ao carregar o histórico.' });
  }
};

// Apaga uma análise do histórico (só as do próprio usuário).
const deleteHistoryItem = async (req, res) => {
  try {
    const { count } = await prisma.codeAnalysis.deleteMany({ where: { id: req.params.id, userId: req.userId } });
    if (count === 0) return res.status(404).json({ error: 'Análise não encontrada.' });
    return res.status(204).send();
  } catch (error) {
    console.error('Erro ao apagar a análise do histórico:', error);
    return res.status(500).json({ error: 'Erro interno ao apagar a análise.' });
  }
};

// Apaga o histórico inteiro do usuário.
const clearHistory = async (req, res) => {
  try {
    const { count } = await prisma.codeAnalysis.deleteMany({ where: { userId: req.userId } });
    return res.status(200).json({ deleted: count });
  } catch (error) {
    console.error('Erro ao limpar o histórico da análise de código:', error);
    return res.status(500).json({ error: 'Erro interno ao limpar o histórico.' });
  }
};

export default { analyzeCode, listHistory, deleteHistoryItem, clearHistory, getAiConfig, fixWithAi, purchaseCredits, fixFullFile };
