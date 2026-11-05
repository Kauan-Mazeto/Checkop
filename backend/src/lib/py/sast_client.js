const SECURITY_ENGINE_URL = process.env.SECURITY_ENGINE_URL || 'http://localhost:8010';
const REQUEST_TIMEOUT_MS = 150000;

export const runSastScan = async ({ files }) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
        const response = await fetch(`${SECURITY_ENGINE_URL}/scans/sast`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ files }),
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