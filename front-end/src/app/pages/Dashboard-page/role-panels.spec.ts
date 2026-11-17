import { Type } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { Finding, Scan } from '../../core/services/scan.service';
import { PLAN_DEFINITIONS } from '../../shared/ui/plans';
import { ROLE_PANEL } from './Dashboard-page.component';
import { DevPanelComponent, PentesterPanelComponent, repeatedTargets, severityCounts, topTypes } from './role-panels';

const finding = (over: Partial<Finding>): Finding => ({
  id: Math.random().toString(36),
  title: 'SQL Injection',
  severity: 'HIGH',
  status: 'OPEN',
  tool: 'ZAP',
  affectedUrl: 'http://localhost:3000/a',
  cveId: null,
  cvssScore: null,
  owaspUrl: 'A03:2021 – Injection',
  remediation: 'Use queries parametrizadas.',
  rawRequest: 'GET /a?q=1',
  rawResponse: 'erro SQL',
  compliance: [],
  createdAt: '2026-11-16T10:00:00Z',
  ...over,
});

const scan = (over: Partial<Scan>): Scan => ({
  id: Math.random().toString(36),
  targetUrl: 'http://localhost:3000',
  objective: 'BASIC_SCAN',
  objectiveLabel: 'Scan básico',
  environment: 'DEVELOPMENT',
  safeMode: false,
  status: 'COMPLETED',
  suspiciousEnvironment: false,
  resolvedIps: ['127.0.0.1'],
  findingsCount: 1,
  createdAt: '2026-11-16T10:00:00Z',
  startedAt: null,
  finishedAt: null,
  ...over,
});

describe('painéis por perfil do Painel', () => {
  it('cada perfil tem o seu painel (ADM usa o de Dev)', () => {
    expect(ROLE_PANEL.QA).toBe('qa');
    expect(ROLE_PANEL.PENTESTER).toBe('pentester');
    expect(ROLE_PANEL.STUDENT).toBe('student');
    expect(ROLE_PANEL.ADM).toBe('dev');
  });

  it('conta por severidade na ordem crítico → informativo', () => {
    const counts = severityCounts([finding({ severity: 'LOW' }), finding({ severity: 'HIGH' }), finding({ severity: 'HIGH' })]);
    expect(counts.map((c) => c.severity)).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
    expect(counts.find((c) => c.severity === 'HIGH')!.count).toBe(2);
  });

  it('tipos mais frequentes juntam os subdomínios num tipo só', () => {
    const types = topTypes([
      finding({ tool: 'SUBFINDER', title: 'Subdomínio encontrado: a.x.com' }),
      finding({ tool: 'SUBFINDER', title: 'Subdomínio encontrado: b.x.com' }),
      finding({ title: 'XSS' }),
    ]);
    expect(types[0]).toEqual({ title: 'Subdomínio encontrado', count: 2 });
  });

  it('URLs repetidas só aparecem com mais de uma análise', () => {
    const list = repeatedTargets([scan({ targetUrl: 'http://a' }), scan({ targetUrl: 'http://a' }), scan({ targetUrl: 'http://b' })]);
    expect(list).toEqual([{ targetUrl: 'http://a', runs: 2 }]);
  });

  describe('Free x Premium', () => {
    beforeEach(() => TestBed.configureTestingModule({ providers: [provideRouter([])] }));

    const render = <T>(type: Type<T>, plan: 'FREE' | 'PREMIUM') => {
      const fixture = TestBed.createComponent(type);
      // setInput dispara o ngOnChanges, como o template do Painel faz
      fixture.componentRef.setInput('findings', [finding({})]);
      if ('scans' in (fixture.componentInstance as object)) fixture.componentRef.setInput('scans', [scan({})]);
      fixture.componentRef.setInput('plan', PLAN_DEFINITIONS[plan]);
      fixture.detectChanges();
      return (fixture.nativeElement as HTMLElement).textContent ?? '';
    };

    it('Dev: correção só no Premium', () => {
      expect(render(DevPanelComponent, 'PREMIUM')).toContain('Use queries parametrizadas.');
      const free = render(DevPanelComponent, 'FREE');
      expect(free).toContain('Correção exata no Premium');
      expect(free).not.toContain('Use queries parametrizadas.');
    });

    it('Pentester: payload e saída bruta só no Premium', () => {
      expect(render(PentesterPanelComponent, 'PREMIUM')).toContain('Payload / requisição');
      const free = render(PentesterPanelComponent, 'FREE');
      expect(free).not.toContain('Payload / requisição');
      expect(free).toContain('Premium');
    });
  });
});
