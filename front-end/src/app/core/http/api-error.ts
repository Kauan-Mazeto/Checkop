import { HttpErrorResponse } from '@angular/common/http';

// Espelha os formatos de erro do backend:
// - validação (Zod, middlewares/auth_validate.js): { error, formattedErrors? }
// - negócio: { error, code? } — ex.: TARGET_NOT_VERIFIED, ACTIVE_SCAN_REQUIRED
interface ApiErrorBody {
  error?: string;
  code?: string;
  formattedErrors?: { field: string; message: string }[];
  [key: string]: unknown;
}

/**
 * Erro de API com o `code` do backend, para a tela reagir a casos específicos
 * (ex.: mostrar o atalho de verificação de domínio) e não só exibir texto.
 */
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string | null = null,
    readonly body: ApiErrorBody | null = null
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export const toApiError = (error: HttpErrorResponse): ApiError => {
  const body = (error.error as ApiErrorBody | null) ?? null;

  let message = 'Erro inesperado. Tente novamente.';
  if (body?.formattedErrors?.length) {
    message = body.formattedErrors.map((issue) => issue.message).join(' ');
  } else if (body?.error) {
    message = body.error;
  } else if (error.status === 0) {
    message = 'Não foi possível conectar ao servidor. Verifique sua conexão.';
  }

  return new ApiError(message, error.status, body?.code ?? null, body);
};
