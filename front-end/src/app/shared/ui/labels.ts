import { UserRole } from '../../core/services/auth.service';
import { FindingSeverity, ScanEnvironment, ScanStatus } from '../../core/services/scan.service';

export const SEVERITY_ORDER: FindingSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export const SEVERITY_LABEL: Record<FindingSeverity, string> = {
  CRITICAL: 'Crítico',
  HIGH: 'Alto',
  MEDIUM: 'Médio',
  LOW: 'Baixo',
  INFO: 'Informativo',
};

// Mesma paleta dos tokens do projeto. espec.txt 2.2: crítico/alto vermelho,
// médio amarelo, baixo/informativo azul.
export const SEVERITY_COLOR: Record<FindingSeverity, string> = {
  CRITICAL: '#e5484d',
  HIGH: '#ef8a4c',
  MEDIUM: '#e9b949',
  LOW: '#6aa6f8',
  INFO: '#8b93a5',
};

export const STATUS_LABEL: Record<ScanStatus, string> = {
  PENDING: 'Pendente',
  RUNNING: 'Em execução',
  COMPLETED: 'Concluído',
  FAILED: 'Falhou',
};

export const ENVIRONMENT_LABEL: Record<ScanEnvironment, string> = {
  DEVELOPMENT: 'DEV',
  STAGING: 'STAGING',
  PRODUCTION: 'PROD',
};

export const ROLE_LABEL: Record<UserRole, string> = {
  QA: 'QA',
  DEV: 'Dev',
  PENTESTER: 'Pentester',
  STUDENT: 'Estudante',
  ADM: 'Admin',
};

export const TOOL_LABEL: Record<string, string> = {
  ZAP: 'OWASP ZAP',
  NUCLEI: 'Nuclei',
  SUBFINDER: 'Subfinder',
  SAST: 'Semgrep',
};

/** "A03:2021 – Injection" -> "A03 Injection" (rótulo curto para gráficos). */
export const shortOwasp = (category: string | null | undefined): string => {
  if (!category || category === 'UNKNOWN') return 'Sem categoria';
  const match = /^(A\d{2}):\d{4}\s*[–-]\s*(.+)$/.exec(category);
  return match ? `${match[1]} ${match[2]}` : category;
};

// Explicação em linguagem simples por categoria do OWASP Top 10 (perfil
// Estudante, RF-11 / RF-25).
export const OWASP_EXPLANATION: Record<string, string> = {
  A01: 'Controle de acesso quebrado: alguém consegue ver ou fazer algo que não deveria, como abrir dados de outro usuário.',
  A02: 'Falha criptográfica: dados sensíveis trafegam ou ficam guardados sem proteção adequada.',
  A03: 'Injeção: o site trata o que o usuário digita como comando (SQL, HTML, sistema), permitindo executar código malicioso.',
  A04: 'Design inseguro: a proteção não foi pensada desde o projeto da funcionalidade.',
  A05: 'Configuração insegura: servidor ou aplicação com opções padrão, cabeçalhos ausentes ou informações expostas.',
  A06: 'Componentes desatualizados: bibliotecas ou servidores com vulnerabilidades já conhecidas publicamente.',
  A07: 'Falha de autenticação: login, sessão ou senha podem ser burlados ou adivinhados.',
  A08: 'Falha de integridade: o sistema confia em código ou dados sem verificar se foram alterados.',
  A09: 'Falha de log e monitoramento: um ataque pode acontecer sem que ninguém perceba.',
  A10: 'SSRF: o servidor pode ser induzido a acessar endereços internos a pedido do atacante.',
};

export const owaspExplanation = (category: string | null | undefined): string | null => {
  const code = /^(A\d{2})/.exec(category ?? '')?.[1];
  return code ? (OWASP_EXPLANATION[code] ?? null) : null;
};
