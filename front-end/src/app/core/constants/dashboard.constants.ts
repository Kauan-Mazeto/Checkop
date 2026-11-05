import type { UserRole } from '../services/auth.service';
import type { FindingSeverity, Scan, ScanObjective } from '../services/scan.service';
import type { PlanDefinition, PlanTier } from '../services/plan.service';

// Cada perfil vê UM painel extra além do núcleo comum (scan, métricas,
// histórico). ADM reaproveita o painel de DEV, como já era no dashboard anterior.
export type RolePanel = 'qa' | 'dev' | 'pentester' | 'student';

export const ROLE_PANEL: Record<UserRole, RolePanel> = {
  QA: 'qa',
  DEV: 'dev',
  PENTESTER: 'pentester',
  STUDENT: 'student',
  ADM: 'dev',
};

export const ROLE_LABEL: Record<UserRole, string> = {
  QA: 'QA',
  DEV: 'Dev',
  PENTESTER: 'Pentester',
  STUDENT: 'Estudante',
  ADM: 'Admin',
};

export const STATUS_LABEL: Record<Scan['status'], string> = {
  PENDING: 'Pendente',
  RUNNING: 'Em execução',
  COMPLETED: 'Concluído',
  FAILED: 'Falhou',
};

export const ENVIRONMENT_LABEL: Record<Scan['environment'], string> = {
  DEVELOPMENT: 'DEV',
  STAGING: 'STAGING',
  PRODUCTION: 'PROD',
};

export const ENVIRONMENT_LONG_LABEL: Record<Scan['environment'], string> = {
  DEVELOPMENT: 'Desenvolvimento',
  STAGING: 'Homologação',
  PRODUCTION: 'Produção',
};

// Rótulos dos objetivos de scan. Espelha SCAN_OBJECTIVES (label) em
// backend/src/constants/scan_objectives.js.
// BACKEND: se isso virar fonte única, o servidor pode expor os objetivos
// (ex.: GET /api/scans/objectives) e esta lista some do front.
export const OBJECTIVE_LABEL: Record<ScanObjective, string> = {
  FULL_SCAN: 'Varredura completa (todas as categorias)',
  SQL_INJECTION: 'Injeção de SQL (SQLi)',
  XSS: 'Cross-Site Scripting (XSS)',
  CSRF: 'Cross-Site Request Forgery (CSRF)',
  SSRF: 'Server-Side Request Forgery (SSRF)',
  OPEN_REDIRECT: 'Open Redirect',
  KNOWN_CVE: 'CVEs conhecidas e má configuração',
  SUBDOMAIN_ENUM: 'Enumeração de subdomínios',
};

export const OBJECTIVE_OPTIONS = Object.keys(OBJECTIVE_LABEL) as ScanObjective[];

// De quanto em quanto tempo o dashboard consulta o backend enquanto houver um
// scan em execução (RUNNING).
export const SCAN_POLL_INTERVAL_MS = 5000;

export const SEVERITY_LABEL: Record<FindingSeverity, string> = {
  CRITICAL: 'Crítica',
  HIGH: 'Alta',
  MEDIUM: 'Média',
  LOW: 'Baixa',
  INFO: 'Info',
};

export const SEVERITY_ORDER: FindingSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export const PLAN_ORDER: PlanTier[] = ['free', 'premium'];

// Plano assumido enquanto o backend não informar o plano do usuário.
// Troque para 'premium' só para testar a visão Premium localmente.
export const DEFAULT_PLAN: PlanTier = 'free';

// BACKEND: se os planos passarem a ser geridos no servidor, troque por
// GET /api/plans. O preço do Premium é um valor de demonstração.
export const PLAN_DEFINITIONS: Record<PlanTier, PlanDefinition> = {
  free: {
    id: 'free',
    name: 'Free',
    priceLabel: 'Para começar',
    dailyScanLimit: 1,
    canChooseObjective: false,
    // Scan básico = só Nuclei com templates de CVEs conhecidas e má
    // configuração (objetivo KNOWN_CVE em scan_objectives.js): é o mais leve,
    // sem varredura ativa do ZAP. O backend não tem um objetivo "BASIC" próprio;
    // se criar um, troque aqui.
    defaultObjective: 'KNOWN_CVE',
    canViewHistory: false,
    canExportReports: false,
    features: [
      { label: '1 scan por dia', included: true },
      { label: 'Scan básico da URL', included: true },
      { label: 'Escolher o tipo de teste', included: false },
      { label: 'Histórico de análises', included: false },
      { label: 'Exportar relatório', included: false },
    ],
  },
  premium: {
    id: 'premium',
    name: 'Premium',
    priceLabel: 'R$ 79/mês',
    dailyScanLimit: null,
    canChooseObjective: true,
    defaultObjective: 'FULL_SCAN',
    canViewHistory: true,
    canExportReports: true,
    features: [
      { label: 'Scans ilimitados', included: true },
      { label: 'Escolher o tipo de teste', included: true },
      { label: 'Scans mais completos', included: true },
      { label: 'Histórico completo de análises', included: true },
      { label: 'Exportar relatório (PDF e JSON)', included: true },
    ],
  },
};
