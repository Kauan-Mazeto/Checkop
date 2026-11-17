// Créditos de IA: a correção do arquivo inteiro com IA é paga à parte (não está
// incluída no Premium). Cada correção completa de um arquivo consome FULL_FIX_COST.
// Valores DEMONSTRATIVOS: como a troca de plano, a compra no TCC não cobra nada
// (sem gateway de pagamento); a regra de débito e saldo é a real.

export const FULL_FIX_COST = 1;

export const AI_CREDIT_PACKS = Object.freeze([
  Object.freeze({ id: 'PACK_5', credits: 5, priceLabel: 'R$ 9,90' }),
  Object.freeze({ id: 'PACK_20', credits: 20, priceLabel: 'R$ 29,90' }),
  Object.freeze({ id: 'PACK_50', credits: 50, priceLabel: 'R$ 59,90' }),
]);

export const AI_CREDIT_PACK_IDS = AI_CREDIT_PACKS.map((pack) => pack.id);

export const findPack = (id) => AI_CREDIT_PACKS.find((pack) => pack.id === id) ?? null;

export const AI_CREDITS_REQUIRED_CODE = 'AI_CREDITS_REQUIRED';
