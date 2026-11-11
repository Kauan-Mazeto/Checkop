// O que cada plano libera (espec.txt, seções 2 e 3). O corte real é feito no
// backend (finding_serializer.js e plan_middleware.js); aqui é só apresentação.
export interface PlanFeature {
  label: string;
  detail: string;
  free: boolean;
  premium: boolean;
}

export const PLAN_FEATURES: PlanFeature[] = [
  { label: 'Varreduras com os 24 tipos de falha', detail: 'Injeções, configuração, exposição de dados e infraestrutura', free: true, premium: true },
  { label: 'Diagnóstico e severidade', detail: 'Veredito, gráficos e explicação de cada falha', free: true, premium: true },
  { label: 'Histórico e relatório em PDF/JSON', detail: 'Todas as varreduras da conta', free: true, premium: true },
  { label: 'Correção exata de cada falha', detail: 'O que mudar no código ou na configuração', free: false, premium: true },
  { label: 'Prova de conceito (PoC)', detail: 'A requisição enviada e a resposta que confirma a falha', free: false, premium: true },
  { label: 'Painel de compliance', detail: 'Impacto em LGPD (art. 46) e PCI-DSS (req. 6.2.4)', free: false, premium: true },
  { label: 'Análise de código-fonte (SAST)', detail: 'Arquivo com a linha vulnerável destacada e a correção ao lado', free: false, premium: true },
];
