import { runSastScan } from '../lib/py/sast_client.js';

// Recebe { files: { "app.js": "conteúdo..." } } direto do usuário logado.
// Por enquanto não persiste no banco (sem Prisma model próprio ainda),
// devolve o resultado direto pro front montar o code diff.
const analyzeCode = async (req, res) => {
    try {
        const { files } = req.body;

        if (!files || typeof files !== 'object' || Object.keys(files).length === 0) {
            return res.status(400).json({ error: 'Envie ao menos um arquivo em "files".' });
        }

        const result = await runSastScan({ files });
        return res.status(200).json(result);
    } catch (error) {
        console.error('Erro na análise SAST:', error);
        return res.status(502).json({ error: error.message || 'Erro ao executar a análise SAST.' });
    }
};

export default { analyzeCode };