import { z } from 'zod';
import { SCAN_OBJECTIVES } from '../constants/scan_objectives.js';

const MAX_URL_LENGTH = 2048;

// reaproveitado no cadastro de alvos (target_validator.js)
export const httpUrlSchema = z
    .string()
    .trim()
    .max(MAX_URL_LENGTH, `URL não pode exceder ${MAX_URL_LENGTH} caracteres.`)
    .url('URL inválida.')
    .refine((url) => {
      try {
        const parsed = new URL(url);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
      } catch {
        return false;
      }
    }, 'A URL deve usar o protocolo http ou https.')
    .refine((url) => {
      const parsed = new URL(url);
      return !parsed.username && !parsed.password;
    }, 'A URL não pode conter credenciais embutidas.');

export const createScanSchema = z.object({
  targetUrl: httpUrlSchema,
  objective: z.enum(Object.keys(SCAN_OBJECTIVES), {
    errorMap: () => ({ message: `objective deve ser um dos valores: ${Object.keys(SCAN_OBJECTIVES).join(', ')}` }),
  }).default('FULL_SCAN'),
  authorizationConfirmed: z.literal(true, {
    errorMap: () => ({
      message: 'É necessário confirmar que você possui autorização para testar este alvo.',
    }),
  }),
});

export const runScanAuthSchema = z.preprocess((value) => value ?? {}, z.object({
  auth: z
    .object({
      loginUrl: z.string().trim().url('loginUrl deve ser uma URL válida.'),
      usernameField: z.string().min(1),
      passwordField: z.string().min(1),
      username: z.string().min(1),
      password: z.string().min(1),
      loggedInIndicator: z.string().optional(),
    loggedOutIndicator: z.string().optional(),
    })
    .optional(),
  useAjaxSpider: z.boolean().default(false),
  // opt-in de varredura ativa (ataque real) em alvo público verificado.
  // As duas declarações são exigidas juntas: autorização do titular (art. 154-A
  // do CP) e permissão do provedor de hospedagem, já que o servidor pode ser
  // "de uso alheio" (hospedagem compartilhada).
  activeScanConfirmed: z.boolean().default(false),
  hostingTermsConfirmed: z.boolean().default(false),
}).refine((data) => !data.activeScanConfirmed || data.hostingTermsConfirmed, {
  message: 'Para a varredura ativa, confirme também que os termos do seu provedor de hospedagem permitem testes de segurança.',
  path: ['hostingTermsConfirmed'],
}));