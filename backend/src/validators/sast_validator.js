import { z } from 'zod';
import { AI_CREDIT_PACK_IDS } from '../constants/ai_credits.js';
import { MAX_FULL_FIX_CHARS } from '../lib/ai_fix.js';

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

// Correção do arquivo inteiro com IA (paga com créditos)
export const fullFixSchema = z.object({
  filename: z.string().trim().min(1).max(200),
  language: z.string().trim().min(1).max(40),
  code: z.string().min(1, 'Envie o código.').max(MAX_FULL_FIX_CHARS, 'Arquivo grande demais para a correção completa com IA (até 60 mil caracteres).'),
  findings: z
    .array(
      z.object({
        title: z.string().trim().min(1).max(300),
        startLine: z.number().int().min(1),
        endLine: z.number().int().min(1).nullish(),
        description: z.string().max(4000).nullish(),
        remediation: z.string().max(4000).nullish(),
      }),
    )
    .min(1, 'Rode a análise antes: a correção completa usa os achados.')
    .max(100),
});

export const purchaseCreditsSchema = z.object({
  packId: z.enum(AI_CREDIT_PACK_IDS),
});
