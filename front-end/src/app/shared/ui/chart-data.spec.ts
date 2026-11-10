import { countBar, owaspBar, severityCountsFrom, severityDoughnut, timelineLine } from './chart-data';
import { owaspExplanation, shortOwasp } from './labels';

describe('chart-data', () => {
  it('severityDoughnut mantém a ordem crítico → informativo e completa com zero', () => {
    const data = severityDoughnut({ LOW: 2, CRITICAL: 1 });
    expect(data.labels).toEqual(['Crítico', 'Alto', 'Médio', 'Baixo', 'Informativo']);
    expect(data.datasets[0].data).toEqual([1, 0, 0, 2, 0]);
  });

  it('timelineLine preenche os dias sem achados com zero', () => {
    const today = new Date('2026-11-09T12:00:00Z');
    const data = timelineLine({ '2026-11-09': 3, '2026-11-07': 1 }, 3, today);
    expect(data.labels).toEqual(['07/11', '08/11', '09/11']);
    expect(data.datasets[0].data).toEqual([1, 0, 3]);
  });

  it('owaspBar ordena da categoria mais frequente para a menos e encurta o rótulo', () => {
    const data = owaspBar({ 'A05:2021 – Security Misconfiguration': 1, 'A03:2021 – Injection': 4 });
    expect(data.labels).toEqual(['A03 Injection', 'A05 Security Misconfiguration']);
    expect(data.datasets[0].data).toEqual([4, 1]);
  });

  it('countBar usa o nome amigável da ferramenta', () => {
    expect(countBar({ ZAP: 2, NUCLEI: 5 }).labels).toEqual(['Nuclei', 'OWASP ZAP']);
  });

  it('severityCountsFrom conta por severidade', () => {
    expect(severityCountsFrom([{ severity: 'HIGH' }, { severity: 'HIGH' }, { severity: 'INFO' }])).toEqual({
      CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 1,
    });
  });

  it('shortOwasp e owaspExplanation lidam com categoria ausente', () => {
    expect(shortOwasp(null)).toBe('Sem categoria');
    expect(shortOwasp('UNKNOWN')).toBe('Sem categoria');
    expect(owaspExplanation('A03:2021 – Injection')).toContain('Injeção');
    expect(owaspExplanation(null)).toBeNull();
  });
});
