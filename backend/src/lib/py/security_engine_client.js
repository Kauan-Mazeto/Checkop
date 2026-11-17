import { engineRequest } from './engine_http.js';

// (RNF 1)
const SECURITY_ENGINE_URL = process.env.SECURITY_ENGINE_URL || 'http://localhost:8010';
const REQUEST_TIMEOUT_MS = 30 * 60 * 1000; // varredura roda em segundo plano, então pode demorar

// B4: o motor só aceita chamadas com este token. Lido na hora da chamada (e não no
// topo do módulo) para não depender da ordem em que os imports carregam o .env.
export const engineHeaders = () => ({
    'Content-Type': 'application/json',
    'X-Engine-Token': process.env.ENGINE_TOKEN ?? '',
});

export class SecurityEngineError extends Error {
    constructor(message, status) {
        super(message);
        this.name = 'SecurityEngineError';
        this.status = status;
    }
}

export const runNucleiScan = async ({ targetUrl, safeMode, rateLimit, tags, jobId }) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {

        const response = await engineRequest(`${SECURITY_ENGINE_URL}/scans/nuclei`, {
            method: 'POST',
            headers: engineHeaders(),
            body: JSON.stringify({ targetUrl, safeMode, rateLimit, tags, jobId }),
            signal: controller.signal,
        });

        const data = await response.json().catch(() => null);

        if (!response.ok) {
            throw new SecurityEngineError(data?.detail || 'Erro ao executar varredura no motor de segurança.', response.status);
        }

        return data;

    } catch (err) {
        if (err.name === 'AbortError') {
            throw new SecurityEngineError('Tempo limite excedido ao executar a varredura.', 504);
        }

        if (err instanceof SecurityEngineError) {
            throw err;
        }

        throw new SecurityEngineError('Motor de segurança indisponível.', 503);
    } finally {
        clearTimeout(timeoutId);
    }
};


export const runZapScan = async ({ targetUrl, safeMode, activeScan, scannerIds, auth, useAjaxSpider, jobId }) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
        const response = await engineRequest(`${SECURITY_ENGINE_URL}/scans/zap`, {
            method: 'POST',
            headers: engineHeaders(),
            body: JSON.stringify({ targetUrl, safeMode, activeScan, scannerIds, auth, useAjaxSpider, jobId }),
            signal: controller.signal,
        });

        const data = await response.json().catch(() => null);

        if (!response.ok) {
            throw new SecurityEngineError(data?.detail || 'Erro ao executar varredura ZAP no motor de segurança.', response.status);
        }

        return data;
    } catch (err) {
        if (err.name === 'AbortError') {
            throw new SecurityEngineError('Tempo limite excedido ao executar a varredura ZAP.', 504);
        }

        if (err instanceof SecurityEngineError) {
            throw err;
        }
        
        throw new SecurityEngineError('Motor de segurança (ZAP) indisponível.', 503);
    } finally {
        clearTimeout(timeoutId);
    }
};

export const runSubdomainEnum = async ({ domain }) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
        const response = await engineRequest(`${SECURITY_ENGINE_URL}/scans/subdomains`, {
            method: 'POST',
            headers: engineHeaders(),
            body: JSON.stringify({ domain }),
            signal: controller.signal,
        });
        const data = await response.json().catch(() => null);
        if (!response.ok) {
            throw new SecurityEngineError(data?.detail || 'Erro ao enumerar subdomínios.', response.status);
        }
        return data;
    } catch (err) {
        if (err.name === 'AbortError') throw new SecurityEngineError('Tempo limite excedido na enumeração de subdomínios.', 504);
        if (err instanceof SecurityEngineError) throw err;
        throw new SecurityEngineError('Motor de segurança (Subfinder) indisponível.', 503);
    } finally {
        clearTimeout(timeoutId);
    }
};
// RF-45: o motor baixa a versão mais recente dos templates do Nuclei
const TEMPLATE_UPDATE_TIMEOUT_MS = 11 * 60 * 1000;

export const updateNucleiTemplates = async () => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TEMPLATE_UPDATE_TIMEOUT_MS);
    try {
        const response = await engineRequest(`${SECURITY_ENGINE_URL}/templates/update`, {
            method: 'POST',
            headers: engineHeaders(),
            signal: controller.signal,
        });
        const data = await response.json().catch(() => null);
        if (!response.ok) {
            throw new SecurityEngineError(data?.detail || 'Erro ao atualizar os templates do Nuclei.', response.status);
        }
        return data;
    } catch (err) {
        if (err.name === 'AbortError') throw new SecurityEngineError('Tempo limite excedido ao atualizar os templates.', 504);
        if (err instanceof SecurityEngineError) throw err;
        throw new SecurityEngineError('Motor de segurança indisponível.', 503);
    } finally {
        clearTimeout(timeoutId);
    }
};
// textos das regras no idioma do usuário; devolve { original: traduzido }
const TRANSLATE_TIMEOUT_MS = 45 * 1000;

export const translateTexts = async (texts, target) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TRANSLATE_TIMEOUT_MS);
    try {
        const response = await fetch(`${SECURITY_ENGINE_URL}/translate`, {
            method: 'POST',
            headers: engineHeaders(),
            body: JSON.stringify({ texts, target }),
            signal: controller.signal,
        });
        const data = await response.json().catch(() => null);
        if (!response.ok) {
            throw new SecurityEngineError(data?.detail || 'Erro ao traduzir os textos.', response.status);
        }
        return data?.translations ?? {};
    } catch (err) {
        if (err.name === 'AbortError') throw new SecurityEngineError('Tempo limite excedido ao traduzir.', 504);
        if (err instanceof SecurityEngineError) throw err;
        throw new SecurityEngineError('Motor de segurança indisponível para tradução.', 503);
    } finally {
        clearTimeout(timeoutId);
    }
};

// pede ao motor que pare as ferramentas desta varredura; elas devolvem o que já
// encontraram e a chamada original (Nuclei/ZAP) termina normalmente
export const cancelEngineJob = async (jobId) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15 * 1000);
    try {
        const response = await fetch(`${SECURITY_ENGINE_URL}/scans/${encodeURIComponent(jobId)}/cancel`, {
            method: 'POST',
            headers: engineHeaders(),
            signal: controller.signal,
        });
        const data = await response.json().catch(() => null);
        if (!response.ok) {
            throw new SecurityEngineError(data?.detail || 'Erro ao cancelar a varredura no motor.', response.status);
        }
        return data;
    } catch (err) {
        if (err instanceof SecurityEngineError) throw err;
        throw new SecurityEngineError('Motor de segurança indisponível para cancelar.', 503);
    } finally {
        clearTimeout(timeoutId);
    }
};
