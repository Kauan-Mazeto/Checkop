// top 10 do OWASP
const COMPLIANCE_RULES = {
    'A01:2021 – Broken Access Control': [
        { law: 'LGPD', reference: 'Art. 46', message: 'Risco de exposição de dados pessoais sem controle de acesso adequado. Sanções de até 2% do faturamento.' },
        { law: 'PCI-DSS v4.0', reference: 'Requisito 7', message: 'Falha em restringir acesso por necessidade de conhecimento ("need to know").' },
    ],
    'A02:2021 – Cryptographic Failures': [
        { law: 'LGPD', reference: 'Art. 46', message: 'Dados sensíveis podem estar trafegando ou armazenados sem criptografia adequada.' },
        { law: 'PCI-DSS v4.0', reference: 'Requisitos 3 e 4', message: 'Proteção de dados de titulares de cartão em repouso e em trânsito comprometida.' },
    ],
    'A03:2021 – Injection': [
        { law: 'LGPD', reference: 'Art. 46', message: 'Injeção pode permitir vazamento ou alteração de dados pessoais no banco de dados.' },
        { law: 'PCI-DSS v4.0', reference: 'Requisito 6.2.4', message: 'Aplicação tende a ser reprovada em scan ASV trimestral obrigatório.' },
    ],
    'A04:2021 – Insecure Design': [
        { law: 'LGPD', reference: 'Art. 46 (Privacy by Design)', message: 'Falha de projeto que compromete a segurança por padrão exigida pela lei.' },
        { law: 'PCI-DSS v4.0', reference: 'Requisito 6.2', message: 'Ausência de controles de segurança previstos desde a fase de design.' },
    ],
    'A05:2021 – Security Misconfiguration': [
        { law: 'LGPD', reference: 'Art. 46', message: 'Configuração insegura aumenta a superfície de exposição de dados pessoais.' },
        { law: 'PCI-DSS v4.0', reference: 'Requisito 2', message: 'Configurações padrão/inseguras não atendem aos padrões mínimos exigidos.' },
    ],
    'A06:2021 – Vulnerable and Outdated Components': [
        { law: 'PCI-DSS v4.0', reference: 'Requisito 6.3', message: 'Componentes desatualizados com CVEs conhecidas reprovam auditorias PCI.' },
    ],
    'A07:2021 – Identification and Authentication Failures': [
        { law: 'LGPD', reference: 'Art. 46', message: 'Falha de autenticação pode permitir acesso indevido a dados pessoais.' },
        { law: 'PCI-DSS v4.0', reference: 'Requisito 8', message: 'Identificação e autenticação de usuários comprometida.' },
    ],
    'A08:2021 – Software and Data Integrity Failures': [
        { law: 'LGPD', reference: 'Art. 46', message: 'Falta de verificação de integridade pode permitir alteração indevida de dados pessoais.' },
        { law: 'PCI-DSS v4.0', reference: 'Requisito 6.3', message: 'Processo de build/deploy sem verificação de integridade de código e dependências.' },
    ],
    'A09:2021 – Security Logging and Monitoring Failures': [
        { law: 'LGPD', reference: 'Art. 46 e 48', message: 'Sem log adequado, a empresa não consegue detectar nem notificar um incidente com dados pessoais dentro do prazo legal.' },
        { law: 'PCI-DSS v4.0', reference: 'Requisito 10', message: 'Rastreamento e monitoramento de todo acesso a dados de titulares de cartão comprometido.' },
    ],
    'A10:2021 – Server-Side Request Forgery': [
        { law: 'LGPD', reference: 'Art. 46', message: 'SSRF pode ser usado como vetor para acessar dados pessoais em sistemas internos.' },
    ],
};

export const getComplianceNotes = (owaspCategory) => COMPLIANCE_RULES[owaspCategory] ?? [];