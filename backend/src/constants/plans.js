// Regras de negócio de cada plano. Fonte única: controllers e middlewares leem
// estes campos e nunca comparam o nome do plano diretamente.
//
// Free  = diagnóstico básico: 1 varredura por dia, sempre o scan básico
//         (passivo), só o último resultado visível e sem correção/PoC/compliance
//         (o corte desses campos fica em lib/py/finding_serializer.js).
// Premium = tudo liberado.
//
// O front espelha estas regras só para avisar o usuário; quem garante é a API.

export const PLAN_RULES = Object.freeze({
  FREE: Object.freeze({
    dailyScanLimit: 1,
    allowedObjectives: Object.freeze(['BASIC_SCAN']),
    defaultObjective: 'BASIC_SCAN',
    // quantas varreduras (as mais recentes) o usuário enxerga; null = todas
    visibleScans: 1,
    // relatórios em PDF/JSON/CSV (individual e consolidado)
    canExportReports: false,
  }),
  PREMIUM: Object.freeze({
    dailyScanLimit: null,
    allowedObjectives: null, // null = todos
    defaultObjective: 'FULL_SCAN',
    visibleScans: null,
    canExportReports: true,
  }),
});

/** Plano desconhecido ou ausente cai no mais restrito. */
export const planRules = (plan) => PLAN_RULES[plan] ?? PLAN_RULES.FREE;

export const isObjectiveAllowed = (plan, objective) => {
  const allowed = planRules(plan).allowedObjectives;
  return allowed === null || allowed.includes(objective);
};

/** Início do dia corrente no fuso do servidor (o limite diário zera à meia-noite). */
export const startOfToday = (now = new Date()) => {
  const start = new Date(now);
  start.setHours(0, 0, 0, 0);
  return start;
};

export const PREMIUM_REQUIRED_CODE = 'PREMIUM_REQUIRED';
export const DAILY_LIMIT_CODE = 'DAILY_SCAN_LIMIT';
