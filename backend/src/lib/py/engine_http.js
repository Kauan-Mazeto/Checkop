import http from 'node:http';
import https from 'node:https';

// Requisição ao motor sem o limite interno do fetch do Node: o fetch (undici)
// desiste depois de 5 min esperando os cabeçalhos da resposta, e uma varredura
// completa do Nuclei passa disso. Aqui o limite é só o AbortSignal de quem chama.
// Devolve o mesmo formato usado do fetch: { ok, status, json() }.
export const engineRequest = (url, { method = 'GET', headers = {}, body, signal } = {}) =>
  new Promise((resolve, reject) => {
    const target = new URL(url);
    const client = target.protocol === 'https:' ? https : http;
    const payload = body === undefined ? undefined : Buffer.from(body);

    const request = client.request(
      target,
      {
        method,
        signal,
        headers: { ...headers, ...(payload ? { 'Content-Length': payload.length } : {}) },
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('error', reject);
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          resolve({
            ok: response.statusCode >= 200 && response.statusCode < 300,
            status: response.statusCode,
            json: async () => JSON.parse(text),
          });
        });
      },
    );

    // o socket fica aberto o tempo que a varredura levar
    request.setTimeout(0);
    request.on('error', (error) => {
      // mesmo nome do fetch, para os handlers de timeout continuarem valendo
      if (error.name === 'AbortError' || error.code === 'ABORT_ERR') {
        const abort = new Error('A requisição ao motor foi abortada.');
        abort.name = 'AbortError';
        return reject(abort);
      }
      reject(error);
    });
    if (payload) request.write(payload);
    request.end();
  });
