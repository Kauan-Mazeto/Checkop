const PLAN_RANK = { FREE: 0, PREMIUM: 1 };

/** Bloqueia o recurso para quem não tem o plano mínimo (espec.txt: SAST é Premium). */
export const requirePlan = (minimum) => (req, res, next) => {
  if ((PLAN_RANK[req.userPlan] ?? 0) >= PLAN_RANK[minimum]) return next();
  return res.status(403).json({
    error: 'Recurso disponível no plano Premium.',
    code: 'PREMIUM_REQUIRED',
  });
};
