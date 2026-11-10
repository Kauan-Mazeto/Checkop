# 01 — Levantamento de pendências do backend

**Data:** 2026-11-09 · **Status:** Concluído (análise, sem alteração de código)

## 1. Objetivo
Comparar tudo o que está documentado (proposta do TCC, [requisitos](../../Requisitos_Funcionalidades_Backend.md), [espec.txt](../../espec.txt), [anotacoes.txt](../../anotacoes.txt)) com o código do backend, para saber o que falta para concluir a aplicação e para a demonstração na apresentação.

## 2. Situação encontrada

### Já implementado
- Autenticação completa: cadastro, login com bloqueio após 5 falhas, login Google, recuperação de senha com código HMAC, revogação de token (`tokenVersion`), exclusão de conta (LGPD).
- Identificação de ambiente (localhost/rede privada → DEVELOPMENT, subdomínio de homologação → STAGING, demais → PRODUCTION) e Modo Seguro em produção (RF-06 a RF-08).
- Orquestração: OWASP ZAP (spider, AJAX spider, passivo, ativo, varredura autenticada), Nuclei (templates por tag, rate limit), Subfinder, Semgrep (SAST).
- Deduplicação de achados entre ferramentas (RF-46), mapeamento para OWASP Top 10 (RF-47), compliance LGPD/PCI-DSS, estatísticas para gráficos, histórico (RF-13), rate limits.

### Bugs e riscos encontrados
Tratados na alteração [02](../02-correcoes-de-seguranca/README.md): classificação OWASP quebrada, banco de dados versionado no git, alvos internos varríveis (SSRF), motor Python sem autenticação, entre outros (B1–B10).

### Lacunas em relação à proposta do TCC
| Item | Situação | Tratado em |
|---|---|---|
| Verificação de propriedade do domínio (objetivo 5 e seção 9 do TCC) | Não existia | [03](../03-verificacao-de-dominio/README.md) |
| Log de auditoria das varreduras (RF-16) | Só logins | [03](../03-verificacao-de-dominio/README.md) |
| Confirmação explícita para varredura ativa em produção (seção 9) | Ativo nunca rodava em produção | [03](../03-verificacao-de-dominio/README.md) |
| Filtro de resultado por perfil de usuário (RF-11) | Não existe | pendente |
| Exportação PDF/JSON (RF-12) | Não existe | pendente |
| Testes automatizados (meta de 60% de cobertura) | Não existiam | iniciado em 02 e 03 |

### Objetivos de varredura: documentados × implementados
| Já existem | Faltam (matriz do `anotacoes.txt`) |
|---|---|
| SQL Injection, XSS, CSRF, SSRF, Open Redirect, CVEs/má configuração, TLS/SSL, DNS/takeover, Varredura completa | Command Injection, Path Traversal/LFI, XXE, SSTI, CRLF, Headers de segurança, Cookies, Clickjacking, CORS, Directory listing, Arquivos expostos, Painéis admin/login padrão, Vazamento de informação, Swagger/GraphQL, Enumeração de subdomínios (código do Subfinder pronto, mas nenhum objetivo o usa) |

Também falta **filtrar o resultado pelo objetivo escolhido**: hoje um scan de "SQL Injection" devolve junto os alertas passivos (headers, cookies).

### Front-end
- A varredura da landing page é **simulada** (resultado fixo no código, `setTimeout` de 1,8 s).
- O dashboard só cadastra a varredura; não escolhe objetivo, não executa e não mostra resultado.

### Requisitos complementares não implementados (opcionais)
RF-14 (2FA), RF-15 (RBAC), RF-17 (cadastro de alvos, coberto em parte pela 03), RF-18 (agendamento), RF-19 (diff entre varreduras), RF-22 (notificações), RF-23 (webhooks CI/CD), RF-24 (Swagger), RF-25 (base de conhecimento), RF-27 (CSV/HTML), RNF-13 (`/api/v1`), RNF-16 (senha forte).

### Divergências entre documentação e código
| Documento diz | Código usa |
|---|---|
| PostgreSQL (TCC 7.3) / SQLite (RNF-06) | SQLite |
| TypeScript no backend | JavaScript (ESM) |
| Fila de tarefas entre API e workers | Chamada HTTP ao motor Python |
| Semgrep fora do escopo (TCC 6.3) | Semgrep integrado (SAST, alinhado ao espec.txt) |

Os documentos precisam ser atualizados para refletir o que foi implementado.

## 3. Ordem de trabalho definida
1. Correções de segurança B1–B10 → [02](../02-correcoes-de-seguranca/README.md)
2. Verificação de domínio + opt-in de varredura ativa → [03](../03-verificacao-de-dominio/README.md)
3. Completar objetivos da matriz e filtrar por objetivo
4. Front-end: fluxo real (objetivo, executar, acompanhar status, tela de resultado)
5. Ensaio da demonstração (site próprio verificado + OWASP Juice Shop local)

## 4. Para os slides
- O backend já orquestra 4 ferramentas open source (ZAP, Nuclei, Subfinder, Semgrep) com um formato único de achado.
- A revisão encontrou e corrigiu 10 problemas de segurança na própria plataforma antes da entrega.
- A maior lacuna em relação à proposta era a verificação de propriedade do alvo, requisito ético e legal central do TCC.
