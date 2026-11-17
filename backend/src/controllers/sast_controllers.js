import { runSastScan } from '../lib/py/sast_client.js';
import { AiFixError, isAiFixEnabled, suggestFix } from '../lib/ai_fix.js';

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
const getAiConfig = (req, res) => res.status(200).json({ enabled: isAiFixEnabled() });

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

export default { analyzeCode, getAiConfig, fixWithAi };
