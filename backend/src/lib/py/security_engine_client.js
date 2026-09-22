// (RNF 1)
const SECURITY_ENGINE_URL = process.env.SECURITY_ENGINE_URL || 'http://localhost:8010';
const REQUEST_TIMEOUT_MS = 5 * 60 * 1000; // Timeout

export class SecurityEngineError extends Error {
    constructor(message, status) {
        super(message);
        this.name = 'SecurityEngineError';
        this.status = status;
    }
}

export const runNucleiScan = async ({ targetUrl, safeMode, rateLimit, tags }) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {

        const response = await fetch(`${SECURITY_ENGINE_URL}/scans/nuclei`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targetUrl, safeMode, rateLimit, tags }),
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


export const runZapScan = async ({ targetUrl, safeMode, scannerIds }) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
        const response = await fetch(`${SECURITY_ENGINE_URL}/scans/zap`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targetUrl, safeMode, scannerIds }),
            signal: controller.signal,
        });
        const data = await response.json().catch(() => null);
        if (!response.ok) {
            throw new SecurityEngineError(data?.detail || 'Erro ao executar varredura ZAP no motor de segurança.', response.status);
        }
        return data;
    } catch (err) {
        if (err.name === 'AbortError') throw new SecurityEngineError('Tempo limite excedido ao executar a varredura ZAP.', 504);
        if (err instanceof SecurityEngineError) throw err;
        throw new SecurityEngineError('Motor de segurança (ZAP) indisponível.', 503);
    } finally {
        clearTimeout(timeoutId);
    }
};

export const runSubdomainEnum = async ({ domain }) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
        const response = await fetch(`${SECURITY_ENGINE_URL}/scans/subdomains`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
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