import { isSelectablePlan } from '../../pages/register-page/register-page.component';
import { PLAN_CARDS, PLAN_DEFINITIONS, planOf, scansCreatedToday, scansRemainingToday } from './plans';

describe('regras de plano (espelham backend/src/constants/plans.js)', () => {
  const now = new Date(2026, 10, 16, 15, 0);
  const at = (d: Date) => ({ createdAt: d.toISOString() });

  it('sem plano informado vale o Free', () => {
    expect(planOf(null).id).toBe('FREE');
    expect(planOf({}).id).toBe('FREE');
    expect(planOf({ plan: 'PREMIUM' }).id).toBe('PREMIUM');
  });

  it('Free: 1 por dia, scan básico, sem histórico, sem relatório e sem detalhes', () => {
    const free = PLAN_DEFINITIONS.FREE;
    expect(free.dailyScanLimit).toBe(1);
    expect(free.canChooseObjective).toBeFalse();
    expect(free.defaultObjective).toBe('BASIC_SCAN');
    expect(free.canViewHistory).toBeFalse();
    expect(free.canExportReports).toBeFalse();
    expect(free.canSeeDetails).toBeFalse();
  });

  it('Premium libera tudo', () => {
    const premium = PLAN_DEFINITIONS.PREMIUM;
    expect(premium.dailyScanLimit).toBeNull();
    expect(premium.canChooseObjective && premium.canViewHistory && premium.canExportReports && premium.canSeeDetails).toBeTrue();
  });

  it('cartões da landing/cadastro batem com as regras e o Enterprise é só vitrine', () => {
    const byId = Object.fromEntries(PLAN_CARDS.map((c) => [c.id, c]));
    expect(PLAN_CARDS.map((c) => c.id)).toEqual(['FREE', 'PREMIUM', 'ENTERPRISE']);
    expect(byId['FREE'].included).toContain(`${PLAN_DEFINITIONS.FREE.dailyScanLimit} scan por dia`);
    expect(byId['PREMIUM'].price.replace(/\s/g, '')).toBe(PLAN_DEFINITIONS.PREMIUM.priceLabel.replace(/\s|\/mês/g, ''));
    expect(byId['ENTERPRISE'].available).toBeFalse();
    expect(isSelectablePlan('ENTERPRISE')).toBeFalse();
    expect(isSelectablePlan('PRO')).toBeFalse(); // rascunho antigo
    expect(isSelectablePlan('PREMIUM')).toBeTrue();
  });

  it('conta só as varreduras de hoje', () => {
    const scans = [at(new Date(2026, 10, 16, 9)), at(new Date(2026, 10, 15, 23, 59)), at(new Date(2026, 10, 16, 0, 1))];
    expect(scansCreatedToday(scans, now)).toBe(2);
  });

  it('restantes hoje: Free zera depois de 1; Premium é ilimitado (null)', () => {
    expect(scansRemainingToday(PLAN_DEFINITIONS.FREE, [], now)).toBe(1);
    expect(scansRemainingToday(PLAN_DEFINITIONS.FREE, [at(new Date(2026, 10, 16, 8))], now)).toBe(0);
    expect(scansRemainingToday(PLAN_DEFINITIONS.FREE, [at(new Date(2026, 10, 15, 8))], now)).toBe(1);
    expect(scansRemainingToday(PLAN_DEFINITIONS.PREMIUM, [at(new Date(2026, 10, 16, 8))], now)).toBeNull();
  });
});
