import { engineHeaders } from './security_engine_client.js';
import { engineRequest } from './engine_http.js';

const SECURITY_ENGINE_URL = process.env.SECURITY_ENGINE_URL || 'http://localhost:8010';
// análise completa (todas as ferramentas, mais pacotes do Semgrep) pode levar alguns minutos
const REQUEST_TIMEOUT_MS = 6 * 60 * 1000;

export const runSastScan = async ({ files, language, depth = 'COMPLETE' }) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
        const response = await engineRequest(`${SECURITY_ENGINE_URL}/scans/sast`, {
            method: 'POST',
            headers: engineHeaders(),
            body: JSON.stringify({ files, language, depth }),
            signal: controller.signal,
        });
        if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            throw new Error(body.detail || 'Falha ao executar a análise SAST.');
        }
        return await response.json();
    } finally {
        clearTimeout(timeoutId);
    }
};