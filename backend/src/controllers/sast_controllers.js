import { runSastScan } from '../lib/py/sast_client.js';
import { AiFixError, fixWholeFile, isAiFixEnabled, suggestFix } from '../lib/ai_fix.js';
import { AI_CREDITS_REQUIRED_CODE, AI_CREDIT_PACKS, FULL_FIX_COST, findPack } from '../constants/ai_credits.js';
import prisma from '../lib/prisma.js';
import { logAudit, AUDIT_ACTIONS } from '../lib/audit_log.js';

// Recebe { files: { "app.js": "conteúdo..." } } direto do usuário logado.
// Por enquanto não persiste no banco (sem Prisma model próprio ainda),
// devolve o resultado direto pro front montar o code diff.
const analyzeCode = async (req, res) => {
    try {
        const { files } = req.body;

        if (!files || typeof files !== 'object' || Object.keys(files).length === 0) {
            return res.status(400).json({ error: 'Envie ao menos um arquivo em "files".' });
        }

        const result = await runSastScan({ files, language: req.userLanguage });
        return res.status(200).json(result);
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
      message: `${pack.credits} créditos adicionados (demonstração, sem cobrança).`,
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

export default { analyzeCode, getAiConfig, fixWithAi, purchaseCredits, fixFullFile };
