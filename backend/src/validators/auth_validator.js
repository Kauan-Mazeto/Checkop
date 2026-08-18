import { z } from 'zod';

export const registerSchema = z.object({
  name: z.string().trim().min(2, 'Nome deve ter no mínimo 2 caracteres.'),
  email: z.string().trim().toLowerCase().email('E-mail inválido.'),
  password: z.string().min(8, 'Senha deve ter no mínimo 8 caracteres.'),
  role: z.enum(['DEV', 'QA', 'PENTESTER', 'STUDENT']),
  // teria o ADM tambem, mas nao sendo
  // possivel escolher, seria cadastrado de outra
  // maneira, mas por agora deixar assim
});

export const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email('E-mail inválido.'),
  password: z.string().min(1, 'Senha é obrigatória.'),
});

export const googleLoginSchema = z.object({
  credential: z.string().min(1, 'Credencial do Google é obrigatória.'),
});

export const forgotPasswordSchema = z.object({
  email: z.string().trim().toLowerCase().email('E-mail inválido.'),
});

export const resetPasswordSchema = z.object({
  email: z.string().trim().toLowerCase().email('E-mail inválido.'),
  code: z.string().trim().regex(/^\d{6}$/, 'Código deve conter 6 dígitos.'),
  newPassword: z.string().min(8, 'Senha deve ter no mínimo 8 caracteres.'),
});