import type { UserRole } from '../../core/services/auth.service';

// RF-11 - o relatório de cada varredura muda conforme o perfil (proposta do TCC):
//   QA:        interface simplificada, gráficos e exportação de relatórios;
//   DEV:       alertas e modo debug, com a correção em primeiro plano;
//   Pentester: logs técnicos e payloads completos;
//   Estudante: painel educacional (payload cru oculto também no servidor).
export type ReportTab = 'overview' | 'findings' | 'evidence';

export interface RoleView {
  label: string;
  /** aba que abre primeiro no detalhe da varredura */
  defaultTab: ReportTab;
  intro: string;
  /** já abre os achados críticos e altos */
  expandHighRisk: boolean;
  /** mostra regra, ferramenta e CVSS de cada achado */
  technicalDetails: boolean;
  /** mostra a explicação em linguagem simples de cada falha */
  explanations: boolean;
}

export const ROLE_VIEWS: Record<UserRole, RoleView> = {
  QA: {
    label: 'QA',
    defaultTab: 'overview',
    intro: 'Visão de QA: resumo com gráficos e o relatório pronto para anexar ao caso de teste.',
    expandHighRisk: false,
    technicalDetails: false,
    explanations: false,
  },
  DEV: {
    label: 'Dev',
    defaultTab: 'findings',
    intro: 'Visão de Dev: as falhas mais graves já abertas, com a correção, e os avisos técnicos dos motores.',
    expandHighRisk: true,
    technicalDetails: true,
    explanations: false,
  },
  PENTESTER: {
    label: 'Pentester',
    defaultTab: 'evidence',
    intro: 'Visão de Pentester: requisições, payloads e respostas completas, com a regra que detectou cada falha.',
    expandHighRisk: false,
    technicalDetails: true,
    explanations: false,
  },
  STUDENT: {
    label: 'Estudante',
    defaultTab: 'findings',
    intro: 'Modo estudo: cada falha vem com a explicação em linguagem simples. Payloads de ataque ficam ocultos neste perfil.',
    expandHighRisk: true,
    technicalDetails: false,
    explanations: true,
  },
  ADM: {
    label: 'Admin',
    defaultTab: 'findings',
    intro: 'Visão completa de administração.',
    expandHighRisk: true,
    technicalDetails: true,
    explanations: false,
  },
};

export const roleView = (role: UserRole | null | undefined): RoleView => ROLE_VIEWS[role ?? 'DEV'] ?? ROLE_VIEWS.DEV;
