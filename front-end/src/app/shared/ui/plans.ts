import type { AuthUser, UserPlan } from '../../core/services/auth.service';

// O que cada plano libera. Espelha backend/src/constants/plans.js (limite
// diário, objetivo e histórico) e lib/py/finding_serializer.js (correção, PoC
// e compliance). O corte real é feito no servidor; aqui é só para a tela avisar
// antes. Nenhum componente compara o nome do plano: todos leem estes campos.
export interface PlanDefinition {
  id: UserPlan;
  name: string;
  priceLabel: string;
  /** varreduras por dia; null = ilimitado */
  dailyScanLimit: number | null;
  /** false = roda sempre `defaultObjective` (o scan básico) */
  canChooseObjective: boolean;
  defaultObjective: string;
  /** false = só a varredura mais recente fica visível */
  canViewHistory: boolean;
  canExportReports: boolean;
  /** correção exata, PoC e compliance de cada achado */
  canSeeDetails: boolean;
  canAnalyzeCode: boolean;
}

export const PLAN_DEFINITIONS: Record<UserPlan, PlanDefinition> = {
  FREE: {
    id: 'FREE',
    name: 'Free',
    priceLabel: 'R$ 0/mês',
    dailyScanLimit: 1,
    canChooseObjective: false,
    defaultObjective: 'BASIC_SCAN',
    canViewHistory: false,
    canExportReports: false,
    canSeeDetails: false,
    canAnalyzeCode: false,
  },
  PREMIUM: {
    id: 'PREMIUM',
    name: 'Premium',
    priceLabel: 'Grátis na demonstração',
    dailyScanLimit: null,
    canChooseObjective: true,
    defaultObjective: 'FULL_SCAN',
    canViewHistory: true,
    canExportReports: true,
    canSeeDetails: true,
    canAnalyzeCode: true,
  },
};

/** Sem plano informado vale o Free (o mais restrito), como no backend. */
export const planOf = (user: Pick<AuthUser, 'plan'> | null | undefined): PlanDefinition =>
  PLAN_DEFINITIONS[user?.plan ?? 'FREE'] ?? PLAN_DEFINITIONS.FREE;

/** Varreduras criadas hoje (dia local), para o limite diário. */
export const scansCreatedToday = (scans: { createdAt: string }[], now = new Date()): number =>
  scans.filter((scan) => {
    const created = new Date(scan.createdAt);
    return (
      created.getFullYear() === now.getFullYear() &&
      created.getMonth() === now.getMonth() &&
      created.getDate() === now.getDate()
    );
  }).length;

/** null = ilimitado. */
export const scansRemainingToday = (plan: PlanDefinition, scans: { createdAt: string }[], now = new Date()): number | null =>
  plan.dailyScanLimit === null ? null : Math.max(plan.dailyScanLimit - scansCreatedToday(scans, now), 0);

// Comparação mostrada em Planos e em Conta (espec.txt, seções 2 e 3).
export interface PlanFeature {
  label: string;
  detail: string;
  free: boolean;
  premium: boolean;
}

export const PLAN_FEATURES: PlanFeature[] = [
  { label: 'Scan básico da URL', detail: 'Cabeçalhos, cookies, clickjacking, vazamento de informação e TLS', free: true, premium: true },
  { label: 'Diagnóstico e severidade', detail: 'Veredito, gráficos e explicação de cada falha', free: true, premium: true },
  { label: 'Varreduras ilimitadas', detail: 'O Free permite 1 varredura por dia', free: false, premium: true },
  { label: 'Escolher o tipo de teste', detail: 'SQLi, XSS, CVEs, arquivos expostos e mais 20 tipos, ou tudo de uma vez', free: false, premium: true },
  { label: 'Histórico de análises', detail: 'O Free mostra só a varredura mais recente', free: false, premium: true },
  { label: 'Relatório em PDF e JSON', detail: 'Para anexar ao caso de teste ou enviar à equipe', free: false, premium: true },
  { label: 'Correção exata de cada falha', detail: 'O que mudar no código ou na configuração', free: false, premium: true },
  { label: 'Prova de conceito (PoC)', detail: 'A requisição enviada e a resposta que confirma a falha', free: false, premium: true },
  { label: 'Painel de compliance', detail: 'Impacto em LGPD (art. 46) e PCI-DSS (req. 6.2.4)', free: false, premium: true },
  { label: 'Análise de código-fonte (SAST)', detail: 'Arquivo com a linha vulnerável destacada e a correção ao lado', free: false, premium: true },
];
