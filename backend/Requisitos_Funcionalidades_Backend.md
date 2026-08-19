1. Funcionalidades Especificadas na Proposta Original

Estas são as funcionalidades já descritas no documento de proposta formal do TCC, reorganizadas como Requisitos Funcionais (RF).

1.1 Autenticação e Gestão de Usuários
RF-01 — Cadastro de usuário: o sistema deve permitir a criação de conta via e-mail e senha.
RF-02 — Login: o sistema deve permitir autenticação via e-mail/senha.
RF-03 — Login social (OAuth 2.0): o sistema deve permitir login via conta Google.
RF-04 — Recuperação de senha: o sistema deve permitir que o usuário redefina sua senha em caso de esquecimento.
RF-05 — Perfis de usuário: o sistema deve classificar cada usuário em um dos perfis: Desenvolvedor (DEV), Analista de QA, Pentester ou Estudante.
1.2 Identificação de Ambiente e Modos de Exibição
RF-06 — Identificação automática de ambiente: o sistema deve detectar automaticamente se a URL-alvo é localhost, ambiente de staging/homologação ou produção.
RF-07 — Modo Verboso: em ambientes de desenvolvimento/homologação, o sistema deve exibir detalhes técnicos completos, stack trace de erros e dados de análise sem mascaramento.
RF-08 — Modo Seguro: em ambientes de produção, o sistema deve filtrar dados sensíveis, restringindo a exibição a cabeçalhos HTTP, códigos de resposta e classificação do tipo de vulnerabilidade.
1.3 Orquestração de Ferramentas de Segurança
RF-09 — Integração com OWASP ZAP: o sistema deve executar varreduras ativas e passivas em aplicações web-alvo via API REST do ZAP.
RF-10 — Integração com Nuclei: o sistema deve executar varreduras baseadas em templates YAML via linha de comando (subprocess).
1.4 Visualização e Relatórios
RF-11 — Dashboard por perfil de usuário: o sistema deve apresentar um painel adaptado a cada perfil:
QA: interface simplificada, gráficos e exportação de relatórios.
DEV: alertas automatizados e modo debug.
Pentester: logs técnicos e payloads completos.
Estudante: painel educacional com explicações contextualizadas.
RF-12 — Exportação de relatórios: o sistema deve gerar relatórios de varredura em formato PDF e JSON.
RF-13 — Histórico de análises: o sistema deve armazenar e exibir o histórico de varreduras realizadas por cada usuário, persistido em banco de dados.
2. Requisitos Não Funcionais Especificados na Proposta Original
RNF-01 — Arquitetura modular: o sistema deve seguir uma arquitetura de microsserviços, separando o backend principal (Node.js/Express) dos módulos de orquestração de segurança (Python).
RNF-02 — Integração contínua: o sistema deve executar testes automatizados a cada commit via GitHub Actions.
RNF-03 — Responsividade e acessibilidade: as interfaces devem ser responsivas e acessíveis em diferentes dispositivos.
RNF-04 — Autenticação stateless: o mecanismo de autenticação deve utilizar JWT, evitando dependência de estado de sessão no servidor.
RNF-05 — Custo de hospedagem controlado: a infraestrutura deve operar dentro da faixa orçamentária estimada (R$ 30,00–R$ 80,00/mês para o plano básico de VPS).
RNF-06 — Persistência relacional: os dados devem ser armazenados em PostgreSQL, com acesso via Prisma ORM.
3. Funcionalidades Propostas (Complementares — Não Existentes na Proposta Original)

Funcionalidades adicionais sugeridas para tornar o produto mais completo, sem sobrepor o que já foi especificado.

3.1 Segurança e Controle de Acesso
RF-14 — Autenticação em dois fatores (2FA): permitir ativação de verificação em duas etapas (TOTP ou e-mail) para reforçar a segurança do login, especialmente relevante em uma plataforma de segurança ofensiva.
RF-15 — Controle de acesso baseado em papéis (RBAC): dentro de uma organização/projeto, permitir papéis como administrador, membro e visualizador, com permissões distintas sobre criação de varreduras e visualização de relatórios.
RF-16 — Log de auditoria: registrar ações relevantes dos usuários (login, criação de varredura, exportação de relatório, alteração de permissões) para fins de rastreabilidade.
3.2 Gestão de Projetos e Varreduras
RF-17 — Cadastro de aplicações/alvos: permitir que o usuário cadastre e nomeie as aplicações que deseja monitorar, em vez de inserir a URL a cada varredura.
RF-18 — Agendamento de varreduras: permitir configurar varreduras recorrentes (ex.: semanal, mensal) para monitoramento contínuo de um alvo.
RF-19 — Comparação entre varreduras (diff): exibir a diferença entre duas varreduras do mesmo alvo, destacando vulnerabilidades novas, corrigidas e persistentes.
RF-20 — Classificação de severidade (CVSS): atribuir pontuação de severidade (baseada em CVSS) às vulnerabilidades encontradas, permitindo priorização.
RF-21 — Sugestões de remediação: para cada vulnerabilidade identificada, exibir orientações básicas de correção, com base em referências públicas (ex.: OWASP Cheat Sheet Series).
3.3 Notificações e Integrações
RF-22 — Notificações automáticas: notificar o usuário (por e-mail e/ou painel interno) quando uma varredura for concluída ou quando vulnerabilidades críticas forem detectadas.
RF-23 — Webhooks de integração com CI/CD: permitir que pipelines externos (ex.: GitHub Actions do próprio usuário) disparem varreduras automaticamente após um deploy.
RF-24 — API pública documentada: disponibilizar endpoints REST documentados (OpenAPI/Swagger) para que equipes integrem o Checkop aos seus próprios fluxos de trabalho.
3.4 Experiência do Usuário e Conteúdo Educacional
RF-25 — Base de conhecimento integrada: para o perfil Estudante, oferecer artigos e explicações contextualizadas sobre cada tipo de vulnerabilidade encontrada.
RF-26 — Ambiente de prática guiada: disponibilizar, dentro da plataforma, links e roteiros de uso de aplicações intencionalmente vulneráveis (DVWA, Juice Shop) para fins didáticos.
RF-27 — Exportação adicional de relatórios: permitir exportação também em CSV e HTML, além de PDF e JSON.
RF-28 — Modo escuro (dark mode): oferecer alternância entre tema claro e escuro na interface.
4. Requisitos Não Funcionais Propostos (Complementares)
RNF-07 — Conformidade com a LGPD: o tratamento de dados pessoais dos usuários deve seguir os princípios da Lei Geral de Proteção de Dados, incluindo consentimento e possibilidade de exclusão de conta.
RNF-08 — Criptografia em trânsito e em repouso: toda comunicação deve ocorrer via HTTPS/TLS, e dados sensíveis (como credenciais e resultados de varredura) devem ser armazenados de forma criptografada.
RNF-09 — Backup automatizado: o banco de dados deve possuir rotina de backup periódico, com possibilidade de restauração.
RNF-10 — Rate limiting: a API deve limitar a taxa de requisições por usuário/IP, prevenindo abuso e ataques de força bruta contra o próprio sistema.
RNF-11 — Observabilidade: o sistema deve implementar logging estruturado e um endpoint de health check, permitindo monitoramento básico de disponibilidade.
RNF-12 — Testes de carga e concorrência: o sistema deve ser avaliado quanto à capacidade de lidar com múltiplas varreduras simultâneas sem degradação significativa de desempenho.
RNF-13 — Versionamento da API: os endpoints da API devem ser versionados (ex.: /api/v1/...), permitindo evolução sem quebrar integrações existentes.
RNF-14 — Internacionalização (i18n): a interface deve ser preparada para suportar múltiplos idiomas no futuro, mesmo que o MVP seja lançado apenas em português.
5. Funcionalidades Específicas de Cibersegurança (Núcleo do Produto)

Esta seção detalha o que efetivamente é analisado durante uma varredura — o "motor" de segurança do Checkop. São as capacidades técnicas que diferenciam a plataforma de um simples painel de relatórios.

5.1 Varredura Passiva (OWASP ZAP)
RF-29 — Análise de cabeçalhos de segurança HTTP: verificar a presença e correta configuração de headers como Content-Security-Policy, Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options e Referrer-Policy.
RF-30 — Análise de cookies: verificar se cookies de sessão possuem os atributos Secure, HttpOnly e SameSite corretamente configurados.
RF-31 — Detecção de vazamento de informações: identificar exposição de mensagens de erro detalhadas, stack traces, comentários de código ou metadados sensíveis nas respostas HTTP.
RF-32 — Análise de certificado TLS/SSL: verificar validade, algoritmo e configuração do certificado, além de identificar uso de protocolos e cifras obsoletos (ex.: TLS 1.0/1.1, SSLv3).
RF-33 — Spidering/crawling do alvo: mapear automaticamente as rotas, formulários e endpoints acessíveis da aplicação antes da varredura ativa, definindo a superfície de ataque.
5.2 Varredura Ativa (OWASP ZAP)
RF-34 — Detecção de Injeção de SQL (SQLi): testar parâmetros de entrada em busca de vulnerabilidades de injeção em banco de dados.
RF-35 — Detecção de Cross-Site Scripting (XSS): identificar pontos de injeção de scripts refletidos, armazenados ou baseados em DOM.
RF-36 — Detecção de Cross-Site Request Forgery (CSRF): verificar ausência de tokens anti-CSRF em formulários e requisições sensíveis.
RF-37 — Detecção de falhas de controle de acesso: identificar exposição de recursos ou endpoints que deveriam exigir autenticação/autorização (ex.: IDOR — Insecure Direct Object Reference).
RF-38 — Detecção de Server-Side Request Forgery (SSRF): testar parâmetros que aceitam URLs em busca de possibilidade de requisições forjadas pelo servidor.
RF-39 — Detecção de Open Redirect: identificar redirecionamentos não validados que possam ser explorados para phishing.
RF-40 — Varredura autenticada: permitir que o usuário forneça credenciais de teste para que a varredura cubra áreas restritas da aplicação (pós-login), não apenas páginas públicas.
5.3 Varredura por Templates (Nuclei)
RF-41 — Detecção de CVEs conhecidas: identificar vulnerabilidades associadas a versões específicas de frameworks, CMSs e bibliotecas expostas publicamente.
RF-42 — Detecção de má configuração (misconfiguration): identificar painéis administrativos expostos, diretórios com listagem habilitada, e serviços com configuração padrão insegura.
RF-43 — Detecção de exposição de arquivos sensíveis: identificar arquivos como .env, .git/, backups de banco de dados e arquivos de configuração acessíveis publicamente.
RF-44 — Detecção de credenciais padrão (default credentials): testar combinações de usuário/senha padrão em painéis de login conhecidos.
RF-45 — Atualização de templates: o sistema deve permitir a atualização periódica do repositório de templates do Nuclei, garantindo cobertura de vulnerabilidades recém-publicadas.
5.4 Consolidação e Priorização de Resultados
RF-46 — Deduplicação de achados: quando ZAP e Nuclei identificarem a mesma vulnerabilidade por caminhos diferentes, o sistema deve consolidar os achados em um único registro.
RF-47 — Mapeamento para OWASP Top 10: cada vulnerabilidade encontrada deve ser categorizada de acordo com a categoria correspondente do OWASP Top 10 (ex.: A03:2021 – Injection).
RF-48 — Pontuação de risco (CVSS): calcular ou associar uma pontuação CVSS a cada achado, permitindo ordenar os resultados por criticidade (já referenciado como RF-20; aqui detalhado como parte do motor de análise).
RF-49 — Evidências da varredura: armazenar a requisição e resposta HTTP (ou trecho relevante) que comprovam cada vulnerabilidade encontrada, servindo como evidência técnica no relatório.
5.5 Controle Ético e Legal da Varredura
RF-50 — Termo de autorização de escopo: antes de iniciar qualquer varredura, o sistema deve exigir que o usuário declare formalmente possuir autorização para testar o alvo informado, registrando essa confirmação com data/hora.
RF-51 — Limitação de taxa de requisições ao alvo (throttling): o motor de varredura deve limitar a quantidade de requisições por segundo enviadas ao alvo, evitando causar indisponibilidade (efeito de negação de serviço) durante o teste.
RF-52 — Modo de varredura não destrutiva: por padrão, o sistema deve evitar testes que possam alterar ou apagar dados reais do alvo (ex.: envio de payloads destrutivos em formulários de escrita), sobretudo quando o ambiente identificado for produção.
6. Observação Metodológica

As seções 1 e 2 refletem exatamente o que já foi definido na proposta formal do TCC (nenhuma funcionalidade foi renomeada ou duplicada). As seções 3 e 4 apresentam extensões que dialogam com o escopo original — reforçando os pilares de segurança, diferenciação por perfil e produção de relatórios — sem reintroduzir itens já listados como fora do escopo do MVP (Nmap, Semgrep, integração com GitHub/GitLab, cobrança/SaaS, aplicações móveis). A seção 5 detalha, no nível técnico, o que os RF-09 e RF-10 (integração com ZAP e Nuclei) efetivamente entregam como capacidade de análise — sem duplicar os requisitos já listados, apenas aprofundando o "motor" de varredura do produto.

7. Backlog de Segurança da Própria Aplicação (Hardening — Implementar Depois)

Diferente da Seção 5 (que trata do motor de varredura — o que o Checkop analisa em outras aplicações), esta seção reúne o que precisa ser reforçado na segurança do próprio Checkop como sistema. São itens identificados tanto no planejamento quanto durante a implementação do módulo de autenticação, ainda não implementados, para tratamento futuro priorizado.

7.1 Autenticação e Sessão
RNF-15 — Rate limiting no login/cadastro: limitar tentativas de POST /login e POST /register por IP/e-mail em uma janela de tempo, prevenindo força bruta de senha e abuso de cadastro automatizado. (Aprofunda o RNF-10 já existente, aplicando especificamente às rotas de autenticação.)
RNF-16 — Política de senha forte: exigir na validação (Zod) uma combinação mínima de maiúscula, minúscula, número e caractere especial, além do tamanho mínimo já existente, rejeitando senhas triviais ou presentes em listas públicas de senhas vazadas.
RNF-17 — Revogação de token (logout real / blacklist): implementar mecanismo para invalidar um JWT antes do seu vencimento natural (ex.: tabela de tokens revogados, ou migração para refresh tokens de curta duração), cobrindo o cenário de token vazado ou dispositivo comprometido.
RNF-18 — Autenticação em dois fatores (2FA): já listado como RF-14; reforçado aqui como item prioritário de hardening, dado que o sistema lida com resultados de varreduras de segurança de terceiros.
RNF-19 — Hash do token de reset de senha: o campo resetPasswordToken não deve ser armazenado em texto puro — deve ser hasheado (ex.: SHA-256) antes de salvar, comparando o hash no momento da validação do link de recuperação.
7.2 Transporte e Infraestrutura
RNF-20 — HTTPS/TLS obrigatório em produção: todo tráfego entre cliente e servidor deve ser criptografado; a aplicação não deve aceitar tráfego HTTP puro fora do ambiente de desenvolvimento local. (Aprofunda o RNF-08 já existente.)
RNF-21 — Gestão de segredos: JWT_SECRET, credenciais de banco e demais segredos não devem circular em texto puro em prints, documentos ou repositórios — devem ser gerados por ferramenta criptográfica adequada e rotacionados periodicamente, especialmente após qualquer exposição acidental.
RNF-22 — Cabeçalhos de segurança HTTP na própria aplicação: garantir que o Checkop aplique a si mesmo os mesmos cabeçalhos que audita em terceiros (CSP, HSTS, X-Frame-Options), reforçando a configuração padrão do helmet() já em uso.
7.3 Auditoria e Conformidade
RNF-23 — Log de auditoria de autenticação: registrar tentativas de login (sucesso e falha), com timestamp e IP de origem, para detecção de padrões suspeitos. (Complementa o RF-16 já existente, aplicando-o especificamente ao fluxo de auth.)
RNF-24 — Conformidade com a LGPD: já listado como RNF-07; reforçado aqui com itens concretos — consentimento explícito no cadastro, mecanismo de exclusão de conta com apagamento efetivo dos dados pessoais, e política de privacidade acessível na interface.
RNF-25 — Minimização de dados em respostas de erro: garantir que mensagens de erro (ex.: 500 Internal Server Error) nunca vazem detalhes internos (stack trace, versão de biblioteca, caminho de arquivo) em ambiente de produção — hoje o console.error já isola isso do cliente, mas vale validar antes do deploy