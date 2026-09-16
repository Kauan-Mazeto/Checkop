import { z } from 'zod';

const MAX_URL_LENGTH = 2048;

export const createScanSchema = z.object({
  targetUrl: z
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
      // rejeita urls com algo embutido ( pode ser malicioso )
      const parsed = new URL(url);
      return !parsed.username && !parsed.password;
    }, 'A URL não pode conter credenciais embutidas.'),
  authorizationConfirmed: z.literal(true, {
    errorMap: () => ({
      message: 'É necessário confirmar que você possui autorização para testar este alvo.',
    }),
  }),
});