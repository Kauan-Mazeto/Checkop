import { z } from 'zod';

// Janela de código enviada para a correção com IA (não o arquivo inteiro).
const MAX_FIX_CODE_CHARS = 20000;

export const aiFixSchema = z
  .object({
    code: z.string().min(1, 'Envie o trecho de código.').max(MAX_FIX_CODE_CHARS, 'Trecho grande demais para a correção com IA.'),
    firstLine: z.number().int().min(1),
    startLine: z.number().int().min(1),
    endLine: z.number().int().min(1),
    language: z.string().trim().min(1).max(40),
    title: z.string().trim().min(1).max(300),
    description: z.string().max(4000).nullish(),
    remediation: z.string().max(4000).nullish(),
  })
  .refine((data) => data.endLine >= data.startLine, { message: 'Intervalo de linhas inválido.', path: ['endLine'] });
