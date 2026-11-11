import { z } from 'zod';
import { httpUrlSchema } from './scan_validator.js';

export const createTargetSchema = z.object({
  url: httpUrlSchema,
  method: z.enum(['DNS_TXT', 'HTTP_FILE', 'META_TAG'], {
    errorMap: () => ({ message: 'method deve ser DNS_TXT, HTTP_FILE ou META_TAG.' }),
  }),
});
