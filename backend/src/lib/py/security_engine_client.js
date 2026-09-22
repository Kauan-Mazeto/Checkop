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

export const runNucleiScan = async ({ targetUrl, safeMode, rateLimit }) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
        const response = await fetch(`${SECURITY_ENGINE_URL}/scans/nuclei`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targetUrl, safeMode, rateLimit }),
            signal: controller.signal,
        });

        const data = await response.json().catch(() => null);

        if (!response.ok) {
            throw new SecurityEngineError(
                data?.detail || 'Erro ao executar varredura no motor de segurança.',
                response.status
            );
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