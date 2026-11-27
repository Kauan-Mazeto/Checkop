import Anthropic from '@anthropic-ai/sdk';
import { zodOutputFormat } from '@anthropic-ai/sdk/helpers/zod';
import { ApiError as GeminiApiError, GoogleGenAI } from '@google/genai';
import { z } from 'zod/v4';

// Provedor de IA do Checkop, escolhido no .env do servidor:
//   AI_PROVIDER=anthropic  -> Claude (ANTHROPIC_API_KEY), pago por uso
//   AI_PROVIDER=gemini     -> Google Gemini (GEMINI_API_KEY), tem plano gratuito
// Sem AI_PROVIDER: usa o que tiver credencial (Anthropic primeiro).
// Política de Privacidade, itens 2.4, 2.5 e 4: o texto cita os dois provedores e
// a tela da Ajuda por IA mostra qual está em uso.

export const ANTHROPIC_MODEL = process.env.AI_FIX_MODEL?.trim() || 'claude-opus-5-5';
// Flash básico do Google, com plano gratuito na API
export const GEMINI_MODEL = process.env.GEMINI_MODEL?.trim() || 'gemini-3.5-flash-lite';

const hasAnthropic = () => Boolean(process.env.ANTHROPIC_API_KEY?.trim() || process.env.ANTHROPIC_AUTH_TOKEN?.trim());
const hasGemini = () => Boolean(process.env.GEMINI_API_KEY?.trim());

/** 'anthropic' | 'gemini' | null (sem credencial) */
export const aiProvider = () => {
  const chosen = process.env.AI_PROVIDER?.trim().toLowerCase();
  if (chosen === 'gemini') return hasGemini() ? 'gemini' : null;
  if (chosen === 'anthropic') return hasAnthropic() ? 'anthropic' : null;
  if (hasAnthropic()) return 'anthropic';
  if (hasGemini()) return 'gemini';
  return null;
};

export const isAiEnabled = () => aiProvider() !== null;

/** Nome para mostrar na tela (quem recebe os dados). */
export const aiProviderLabel = () =>
  ({ anthropic: 'Anthropic (Claude)', gemini: 'Google (Gemini)' })[aiProvider()] ?? null;

export class AiError extends Error {
  constructor(message, code = 'AI_FIX_FAILED') {
    super(message);
    this.name = 'AiError';
    this.code = code;
  }
}

let anthropicClient = null;
let geminiClient = null;
const anthropic = () => (anthropicClient ??= new Anthropic());
const gemini = () => (geminiClient ??= new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY.trim() }));

const busy = () => new AiError('O serviço de IA está ocupado ou atingiu o limite gratuito. Tente de novo em instantes.', 'AI_BUSY');
const unavailable = () => new AiError('A IA está indisponível no momento.', 'AI_NOT_CONFIGURED');

const anthropicError = (error) => {
  if (error instanceof Anthropic.RateLimitError) return busy();
  if (error instanceof Anthropic.AuthenticationError || error instanceof Anthropic.PermissionDeniedError) {
    console.error('[ai] credencial da Anthropic recusada:', error.message);
    return unavailable();
  }
  console.error('[ai] falha na Anthropic:', error instanceof Anthropic.APIError ? `${error.status} ${error.message}` : error);
  return new AiError('Não foi possível gerar a resposta agora. Tente novamente.');
};

const geminiError = (error) => {
  if (error instanceof GeminiApiError) {
    if (error.status === 429 || error.status === 503) return busy();
    if (error.status === 401 || error.status === 403) {
      console.error('[ai] credencial do Gemini recusada:', error.message);
      return unavailable();
    }
    console.error('[ai] falha no Gemini:', error.status, error.message);
  } else {
    console.error('[ai] falha no Gemini:', error);
  }
  return new AiError('Não foi possível gerar a resposta agora. Tente novamente.');
};

/** Fim da resposta do Gemini no mesmo vocabulário da Anthropic. */
const geminiStop = (response) => {
  if (response.promptFeedback?.blockReason) return 'refusal';
  const reason = response.candidates?.[0]?.finishReason;
  if (reason === 'MAX_TOKENS') return 'max_tokens';
  if (reason && !['STOP', 'FINISH_REASON_UNSPECIFIED'].includes(reason)) return 'refusal'; // SAFETY, RECITATION...
  return 'end';
};

/** Conversa no formato do Gemini: "assistant" vira "model"; cada fala tem partes de texto. */
const toGeminiContents = (messages) =>
  messages.map((m) => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: (Array.isArray(m.content) ? m.content : [{ text: m.content }]).map((part) => ({ text: part.text })),
  }));

const ensureEnabled = () => {
  const provider = aiProvider();
  if (!provider) throw new AiError('A IA não está configurada neste servidor.', 'AI_NOT_CONFIGURED');
  return provider;
};

/**
 * Resposta em texto livre (Ajuda por IA).
 * messages: [{ role: 'user'|'assistant', content: string | [{ type:'text', text }] }]
 * Devolve { text, stop: 'end'|'max_tokens'|'refusal', model }.
 */
export const generateText = async ({ system, messages, maxTokens = 16000, timeoutMs = 120000 }) => {
  const provider = ensureEnabled();

  if (provider === 'anthropic') {
    let response;
    try {
      // fallbacks "default": se o modelo recusar por política, o servidor da Anthropic tenta o de reserva
      response = await anthropic().beta.messages.create(
        {
          model: ANTHROPIC_MODEL,
          betas: ['server-side-fallback-2026-07-01'],
          fallbacks: 'default',
          max_tokens: maxTokens,
          output_config: { effort: 'medium' },
          system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
          messages,
        },
        { timeout: timeoutMs },
      );
    } catch (error) {
      throw anthropicError(error);
    }
    const text = response.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n').trim();
    const stop = response.stop_reason === 'refusal' ? 'refusal' : response.stop_reason === 'max_tokens' ? 'max_tokens' : 'end';
    return { text, stop, model: response.model };
  }

  let response;
  try {
    response = await gemini().models.generateContent({
      model: GEMINI_MODEL,
      contents: toGeminiContents(messages),
      config: { systemInstruction: system, maxOutputTokens: maxTokens, httpOptions: { timeout: timeoutMs } },
    });
  } catch (error) {
    throw geminiError(error);
  }
  return { text: (response.text ?? '').trim(), stop: geminiStop(response), model: response.modelVersion ?? GEMINI_MODEL };
};

/**
 * JSON Schema do Zod sem o que o Gemini não precisa: "$schema" e os limites
 * automáticos de inteiro (±9007199254740991) que o Zod põe em .int().
 */
const cleanSchema = (node) => {
  if (Array.isArray(node)) return node.map(cleanSchema);
  if (!node || typeof node !== 'object') return node;
  const out = {};
  for (const [key, value] of Object.entries(node)) {
    if (key === '$schema') continue;
    if ((key === 'minimum' || key === 'maximum') && Math.abs(value) === Number.MAX_SAFE_INTEGER) continue;
    out[key] = cleanSchema(value);
  }
  return out;
};
const geminiSchema = (schema) => cleanSchema(z.toJSONSchema(schema));

/**
 * Resposta estruturada (correção com IA), validada pelo schema Zod.
 * Devolve { parsed | null, stop, model }.
 */
export const generateStructured = async ({ system, user, schema, maxTokens = 16000, timeoutMs = 120000 }) => {
  const provider = ensureEnabled();

  if (provider === 'anthropic') {
    let response;
    try {
      response = await anthropic().beta.messages.parse(
        {
          model: ANTHROPIC_MODEL,
          betas: ['server-side-fallback-2026-07-01'],
          fallbacks: 'default',
          max_tokens: maxTokens,
          output_config: { effort: 'medium', format: zodOutputFormat(schema) },
          system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
          messages: [{ role: 'user', content: user }],
        },
        { timeout: timeoutMs },
      );
    } catch (error) {
      throw anthropicError(error);
    }
    const stop = response.stop_reason === 'refusal' ? 'refusal' : response.stop_reason === 'max_tokens' ? 'max_tokens' : 'end';
    return { parsed: response.parsed_output ?? null, stop, model: response.model };
  }

  let response;
  try {
    response = await gemini().models.generateContent({
      model: GEMINI_MODEL,
      contents: [{ role: 'user', parts: [{ text: user }] }],
      config: {
        systemInstruction: system,
        maxOutputTokens: maxTokens,
        responseMimeType: 'application/json',
        responseJsonSchema: geminiSchema(schema),
        httpOptions: { timeout: timeoutMs },
      },
    });
  } catch (error) {
    throw geminiError(error);
  }
  const stop = geminiStop(response);
  let parsed = null;
  if (stop === 'end' && response.text) {
    try {
      const result = schema.safeParse(JSON.parse(response.text));
      parsed = result.success ? result.data : null;
      if (!result.success) console.error('[ai] JSON do Gemini fora do formato:', result.error.message);
    } catch {
      console.error('[ai] o Gemini não devolveu um JSON válido');
    }
  }
  return { parsed, stop, model: response.modelVersion ?? GEMINI_MODEL };
};
