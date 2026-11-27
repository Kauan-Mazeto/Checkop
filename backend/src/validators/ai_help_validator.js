import { z } from 'zod';

// Ajuda por IA: o navegador manda só qual item (varredura ou análise) e as falas;
// o contexto é montado no servidor a partir do banco (lib/ai_help.js).
export const MAX_CHAT_MESSAGES = 20;
export const MAX_QUESTION_CHARS = 2000;
const MAX_ANSWER_CHARS = 20000;

export const contextQuerySchema = z.object({
  kind: z.enum(['scan', 'code']),
  id: z.string().trim().min(1).max(64),
});

export const aiChatSchema = z
  .object({
    kind: z.enum(['scan', 'code']),
    id: z.string().trim().min(1).max(64),
    messages: z
      .array(
        z.object({
          role: z.enum(['user', 'assistant']),
          content: z.string().trim().min(1).max(MAX_ANSWER_CHARS),
        }),
      )
      .min(1)
      .max(MAX_CHAT_MESSAGES, 'Conversa longa demais: comece uma nova.'),
  })
  // começa e termina com o usuário, alternando; a pergunta tem limite próprio
  .refine((data) => data.messages.every((m, i) => m.role === (i % 2 === 0 ? 'user' : 'assistant')), {
    message: 'Conversa fora de ordem.',
    path: ['messages'],
  })
  .refine((data) => data.messages.at(-1).role === 'user', { message: 'A última mensagem deve ser a pergunta.', path: ['messages'] })
  .refine((data) => data.messages.filter((m) => m.role === 'user').every((m) => m.content.length <= MAX_QUESTION_CHARS), {
    message: `Cada pergunta pode ter até ${MAX_QUESTION_CHARS} caracteres.`,
    path: ['messages'],
  });
