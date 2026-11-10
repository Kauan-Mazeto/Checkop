# 04 — Objetivos de varredura da matriz e filtro por objetivo

**Data:** 2026-11-09 · **Status:** Implementado e testado · **Requisitos:** RF-29 a RF-43, RF-47, matriz de cobertura de [anotacoes.txt](../../anotacoes.txt)

## 1. Problema
- **Faltavam opções.** Dos itens que a matriz de cobertura marca como "Sim", 15 não podiam ser escolhidos como objetivo de varredura. A enumeração de subdomínios tinha código pronto (Subfinder), mas nunca era executada.
- **O resultado vinha poluído.** Ao escolher "SQL Injection", o relatório trazia também os alertas passivos do ZAP (headers, cookies...), que não tinham sido pedidos.
- **A revisão achou IDs de regra errados** nos objetivos que já existiam (conferidos na [documentação oficial do ZAP](https://www.zaproxy.org/docs/alerts/)):

  | Objetivo | Estava | Era na verdade | Corrigido para |
  |---|---|---|---|
  | SQL Injection | 90019 | Server Side Code Injection | removido; entrou o 40027 (MsSQL) |
  | XSS | — | faltava o DOM XSS | entrou o 40026 |
  | SSRF | 40047, 40048, 40049 | Text4shell, React2Shell, inexistente | só o 40046 |
  | Open Redirect | 10044 | regra passiva "Big Redirect" | 20019 (External Redirect) |

- **Dois bugs no motor**, confirmados no jar do ZAP 2.17 instalado:
  - A ação `setEnabledScanners` **não existe** na API do ZAP; o nome certo é `enableScanners`. Todo objetivo específico falhava na fase de ataque.
  - A varredura completa não reativava os scanners. Como a seleção do ZAP é global, ela herdava a seleção restrita da varredura anterior.
- Objetivo "só passivo" não tinha como ser expresso: lista vazia de scanners era tratada como "rodar todos", o que dispararia o ataque completo.

## 2. Proposta
1. Cobrir todos os itens da matriz como objetivos selecionáveis.
2. Corrigir os IDs e os bugs do motor.
3. Filtrar o resultado pelo objetivo escolhido.
4. Expor a lista de objetivos para o front montar o seletor.

**Fora do escopo:** os itens que a matriz marca como "Não" (força bruta, IDOR, upload inseguro, lógica de negócio), porque nenhum scanner automático os cobre bem, e a tela do front.

## 3. Decisões tomadas
| Decisão | Opções | Escolha e motivo |
|---|---|---|
| Regras beta do ZAP (CSRF ativo, SSRF, CORS ativo, backup/.git, Advanced SQLi) | Instalação automática · manual documentada | **Automática.** O motor instala `ascanrulesBeta` e `pscanrulesBeta` pela API do ZAP na primeira varredura. Se falhar (sem internet), segue sem elas e avisa no resultado |
| Objetivo que depende de ataque, em site público, sem opt-in | Rodar e avisar · bloquear | **Bloquear** com `400 ACTIVE_SCAN_REQUIRED`. Rodar só o passivo daria um falso "nenhuma falha encontrada" |
| Teste de login padrão (`default-login`) | Sempre · só com opt-in | **Só com opt-in.** Tentar credenciais é ataque (art. 154-A, ver [03](../03-verificacao-de-dominio/README.md)) |
| Como filtrar | Por título · por ID da regra | **Por ID da regra.** Nova coluna `Finding.ruleId` (pluginId do ZAP / template-id do Nuclei) |

## 4. Objetivos disponíveis (24)

| Objetivo | ZAP ativo | ZAP passivo | Nuclei (tags) | Exige ataque | Cobertura |
|---|---|---|---|---|---|
| SQL Injection | 40018–40022, 40024, 40027, 90018β | — | sqli | sim | total |
| XSS | 40012, 40014, 40016, 40017, 40026 | — | xss | sim | total |
| Injeção de comandos | 90020, 90037, 90019 | — | cmdi, rce | sim | total |
| Path Traversal / LFI | 6, 7 | — | lfi | sim | total |
| XXE | 90023 | — | xxe | sim | total |
| SSTI | 90035, 90036 | — | ssti | sim | total |
| CRLF / injeção de cabeçalho | 40003 | — | crlf | sim | total |
| Open Redirect | 20019 | 10028 | redirect | sim | total |
| CSRF | 20012β | 10202 | csrf | não | parcial |
| SSRF | 40046β | — | ssrf | sim | parcial |
| Cabeçalhos de segurança | — | 10020, 10021, 10035, 10038, 10055, 10063β | headers | não | total |
| Cookies | — | 10010, 10011, 10054, 90033 | cookie | não | total |
| Clickjacking | — | 10020 | clickjacking | não | total |
| CORS | 40040β | 10098 | cors | não | total |
| Listagem de diretórios | 0 | 10033 | listing | não | total |
| Arquivos expostos | 40034, 40032, 40035, 40028, 40029, 10095β, 41β, 42β | — | exposure, backup, git, env | não | total |
| Painéis admin / login padrão | — | — | panel (+ default-login com opt-in) | não | total |
| Vazamento de informação | — | 90022, 10023, 10036, 10037, 10061, 10027, 2, 10096, 10097, 10024 | disclosure, debug, error | não | total |
| Swagger / GraphQL | — | — | swagger, graphql | não | total |
| CVEs / componentes | — | — | cve, misconfig | não | total |
| TLS/SSL | — | — | ssl, tls | não | parcial |
| DNS / subdomain takeover | — | — | dns, takeover | não | parcial |
| Enumeração de subdomínios | Subfinder (fontes públicas, não toca o alvo) | | | não | total |
| Varredura completa | todos | todos | todos | — | — |

β = regra beta, instalada automaticamente. As tags do Nuclei foram conferidas contra os 11.788 templates instalados; todas têm templates (a menor, `clickjacking`, tem 1).

## 5. O que foi implementado

### Banco (migrações `objetivos_da_matriz_e_rule_id` e `avisos_dos_motores`)
- 14 valores novos no enum `ScanObjective`.
- `Finding.ruleId`: ID da regra que gerou o achado.
- `Scan.engineWarnings`: avisos dos motores em JSON (regra indisponível, ferramenta que falhou).

### API
- `GET /api/scans/objectives`: lista para o seletor (rótulo, descrição, OWASP, cobertura, se exige ataque), sem expor IDs internos.
- `POST /api/scans/:id/run`: `400 ACTIVE_SCAN_REQUIRED` para objetivo de ataque em site público sem opt-in.
- `GET /api/scans/:id`: passa a incluir `objectiveLabel` e `engineWarnings`.

### Orquestração
- O filtro por objetivo mantém só os alertas do ZAP cujas regras pertencem ao objetivo. Nuclei e Subfinder já rodam restritos pelas tags.
- Objetivo passivo envia `scannerIds: []`: o ZAP não faz nenhum ataque.
- O Subfinder usa o domínio registrável (`www.loja.com.br` → `loja.com.br`) e não roda para localhost/IP.
- Ferramenta que falha vira um aviso genérico no resultado; o detalhe técnico fica só no log.

### Motor Python
- `enableScanners` (nome correto) e `enableAllScanners` na varredura completa.
- Um ID indisponível não derruba a varredura: os scanners são habilitados um a um e os ausentes viram aviso.
- Instalação automática das regras beta, uma vez por processo.
- `ruleId` no achado do ZAP (pluginId) e do Nuclei (template-id).

### Arquivos
`src/constants/scan_objectives.js` (reescrito), `src/controllers/scan_controllers.js`, `src/routes/scan_routes.js`, `prisma/schema.prisma`, `src/py/security_engine/app/{zap_runner,nuclei_runner,schemas,main}.py`

## 6. Como foi validado
- **Node, 64 testes** (`npm test`). Novos:
  - integridade da configuração: todo ID do ZAP pertence à lista oficial; objetivos e enum do Prisma iguais; todo scanner ativo está no filtro; objetivo de ataque tem scanner;
  - regressão dos IDs errados;
  - objetivos passivos sem ataque;
  - filtro do resultado;
  - `default-login` só com opt-in;
  - avisos gravados;
  - bloqueio `ACTIVE_SCAN_REQUIRED`;
  - rota de objetivos.
- **Python, 24 testes** (`npm run test:engine`). Novos:
  - ação `enableScanners` correta;
  - varredura completa reativa tudo;
  - ID ausente vira aviso;
  - instalação das regras beta uma única vez, e a falha vira aviso;
  - objetivo passivo não inicia ataque;
  - `ruleId` no ZAP e no Nuclei.
- **Fontes conferidas:** a documentação oficial de alertas do ZAP e o jar `zap-2.17.0.jar` local (nomes reais das ações da API).
- **Não validado ainda:** execução real contra o ZAP e o Nuclei rodando. Fica para o ensaio da demonstração.

## 7. Limitações e riscos conhecidos
- A instalação das regras beta precisa de internet na primeira varredura, e o ZAP pode pedir reinício em versões antigas. Testar no ensaio.
- As regras beta são menos maduras que as `release` e podem gerar mais falsos positivos.
- SSRF continua parcial: a confirmação depende do servidor de callback (OAST) do Nuclei.
- CSRF continua parcial: detecta a falta de token, não prova a exploração.
- Tempo: objetivos com muitas tags (Arquivos expostos, Painéis, CVEs) rodam milhares de templates a 10 requisições/s e podem levar vários minutos.
- A tela do front ainda não usa `GET /api/scans/objectives` (etapa 05).

## 8. Para os slides
- **24 objetivos de varredura** cobrindo a matriz do TCC: injeções, configuração, exposição, criptografia e reconhecimento.
- O usuário escolhe **o que** testar; o Checkop traduz isso em regras do ZAP, templates do Nuclei ou no Subfinder.
- **Resultado focado:** só aparece o que foi pedido, filtrado pelo ID da regra que gerou o achado.
- **Qualidade:** a revisão encontrou IDs de regra errados e uma ação inexistente na API do ZAP. Testes automatizados conferem a configuração contra a lista oficial.
- **Ética embutida:** objetivos de ataque e testes de credencial só rodam com autorização explícita.
