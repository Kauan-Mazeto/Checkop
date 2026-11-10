# 03 — Verificação de propriedade do alvo e opt-in de varredura ativa

**Data:** 2026-11-09 · **Status:** Implementado e testado · **Requisitos:** objetivo específico 5 e seção 9 do TCC, RF-16, RF-17 (parcial), RF-50, RF-51, RF-52, RNF-24

## 1. Problema
- A única barreira para varrer um site era um checkbox "tenho autorização", e o front já o enviava como `true` automaticamente. Qualquer usuário podia varrer o site de terceiros, o que é crime.
- A proposta do TCC promete: *"Nenhuma varredura deverá ser executada contra um alvo que não tenha sido verificado."*
- Em produção o ataque ativo (que encontra SQL Injection de verdade) nunca rodava, nem no site do próprio usuário. Isso inviabilizava a demonstração com um site real.

## 2. Base legal considerada
> Levantamento feito pela equipe, não substitui parecer jurídico. Validar com a orientadora.

| Norma | O que diz | Consequência no Checkop |
|---|---|---|
| **Código Penal, art. 154-A** (Lei 12.737/2012, alterado pela Lei 14.155/2021) | Crime invadir dispositivo informático **de uso alheio** sem **autorização expressa ou tácita** | Com autorização, a conduta não é crime. O Checkop exige **prova técnica** de controle do alvo e registra a autorização |
| Lei 14.155/2021: mudança para "de uso alheio" | Protege quem **usa** o dispositivo, não só o proprietário | Em hospedagem compartilhada o servidor é usado por terceiros: o opt-in exige declarar que **os termos do provedor de hospedagem permitem** o teste |
| **Marco Civil da Internet** (Lei 12.965/2014), art. 15 | Provedor de aplicação guarda registros de acesso (IP, data e hora) por **6 meses**, em sigilo | Log de auditoria mantido por 6 meses, inclusive após a exclusão da conta |
| **LGPD** (Lei 13.709/2018), arts. 6º, 16 e 46 | Minimização, eliminação ao fim da finalidade, segurança | Auditoria sem e-mail nem credenciais; registros apagados automaticamente após 6 meses; política de privacidade atualizada |
| Requisitos RF-51 e RF-52 | Não causar indisponibilidade nem destruir dados | Throttling do ZAP em produção; templates de DoS sempre bloqueados |

Fontes: [Lei 14.155/2021](https://planalto.gov.br/ccivil_03/_Ato2019-2022/2021/Lei/L14155.htm) · [art. 154-A](https://www.legjur.com/legislacao/art/lei_00141552021-1) · [Empório do Direito: "uso alheio"](https://emporiododireito.com.br/leitura/a-nova-lei-14-155-21-e-o-crime-de-invasao-de-dispositivo-informatico) · [Marco Civil, art. 15](https://modeloinicial.com.br/lei/27460/marco-civil-internet/art-15) · [IBCCRIM: autorização e tipicidade](https://jcc.ibccrim.org.br/ojs2/index.php/JCC/article/download/25/pdf)

## 3. Proposta e fluxo

```
Usuário                          Checkop                              Site do usuário
  │ 1. cadastra alvo (URL+método) ─►│ gera token aleatório                  │
  │◄─ instruções (TXT / arquivo / meta tag)                                 │
  │ 2. publica a prova ──────────────────────────────────────────────────► │
  │ 3. pede verificação ───────────►│ consulta DNS / HTTP (anti-SSRF) ────► │
  │◄─ verificado                    │ grava verifiedAt + auditoria          │
  │ 4. cria varredura ─────────────►│ exige alvo verificado que cubra o host│
  │ 5. executa (+ opt-in de ataque)►│ confere a prova DE NOVO ────────────► │
  │                                 │ registra opt-in (data/hora/IP)        │
  │                                 │ ZAP/Nuclei com throttling ──────────► │
```

### Métodos de verificação (seção 9 do TCC)
| Método | Onde publicar | O que prova |
|---|---|---|
| DNS TXT | `_checkop-challenge.meusite.com` → `checkop-verification=<token>` | O domínio inteiro e os subdomínios |
| Arquivo | `https://www.meusite.com/.well-known/checkop-verification.txt` | Somente aquele host |
| Meta tag | `<meta name="checkop-verification" content="<token>">` na página inicial | Somente aquele host |

É a mesma lógica do Google Search Console (propriedade de domínio × prefixo de URL).

### Regras
- **Alvo público** (STAGING ou PRODUCTION) só é varrido com alvo verificado que cubra o host. Sem isso: `403 TARGET_NOT_VERIFIED`.
- **localhost e rede privada** são isentos (ambiente de desenvolvimento, como define o TCC).
- A prova é **conferida de novo a cada execução**. Se o TXT, o arquivo ou a tag sumiu, ou o domínio mudou de dono, a verificação cai na hora.
- **Ataque ativo em alvo público** exige, a cada execução, `activeScanConfirmed: true` + `hostingTermsConfirmed: true`. Sem o opt-in, roda só a varredura passiva.

## 4. Decisões tomadas
| Decisão | Opções | Escolha e motivo |
|---|---|---|
| Quando exigir verificação | Qualquer varredura pública · só a ativa | **Qualquer varredura pública.** Até o modo passivo e o Nuclei enviam requisições ao alvo; e é o texto do TCC |
| Ataque ativo em produção | Opt-in por execução · nunca | **Opt-in por execução**, depois de pesquisar a lei: a autorização afasta o crime (art. 154-A) |
| Escopo da prova | Igual para todos · por método | **Por método.** DNS prova o domínio; arquivo/meta provam só o host |
| Revalidação | Uma vez · periódica · a cada execução | **A cada execução.** Custa poucos segundos e cobre domínio expirado ou vendido |
| Retenção da auditoria | Indefinida · 6 meses | **6 meses** e eliminação automática (Marco Civil + LGPD) |

## 5. O que foi implementado

### Banco de dados (migração `verificacao_de_dominio_e_auditoria`, só adiciona tabelas e colunas)
- `Target`: alvo do usuário, com método, escopo, token, `verifiedAt` e `lastCheckedAt`.
- `AuditLog`: ação, recurso, IP, user agent e detalhes. O `userId` vira `null` quando a conta é excluída.
- `Scan`: novos campos `targetId`, `activeScanConfirmedAt` e `activeScanConfirmationIp`.

### API
| Rota | Função |
|---|---|
| `POST /api/targets` `{ url, method }` | Cadastra o alvo e devolve as instruções |
| `GET /api/targets` · `GET /api/targets/:id` | Lista / detalha, com as instruções |
| `POST /api/targets/:id/verify` | Verifica (200) ou explica que a prova não foi encontrada (422) |
| `DELETE /api/targets/:id` | Remove o alvo |
| `POST /api/scans/:id/run` | Aceita `activeScanConfirmed` e `hostingTermsConfirmed` |

### Segurança da própria verificação
Verificar faz o servidor buscar uma URL indicada pelo usuário, o que é um vetor de SSRF. A busca:
- só aceita destino público;
- não segue redirecionamento;
- tem timeout de 8 s e limite de 512 KB;
- tem rate limit de 30 verificações por hora.

### Motor Python
- `activeScan` separado do `safeMode`: produção continua com dados mascarados, mas pode atacar com o opt-in.
- Throttling do ZAP em produção: 2 threads por host e 250 ms entre requisições (RF-51).
- Templates `dos` do Nuclei bloqueados sempre, inclusive com o ataque liberado.

### Auditoria (RF-16)
Ações registradas: `TARGET_CREATED`, `TARGET_VERIFIED`, `TARGET_VERIFICATION_FAILED`, `TARGET_DELETED`, `SCAN_CREATED`, `SCAN_BLOCKED`, `SCAN_STARTED` (este último guarda se houve ataque ativo). Uma limpeza roda no boot e a cada 24 h, apagando auditoria e tentativas de login com mais de 6 meses.

### Arquivos
- Novos: `src/lib/target_verification.js`, `src/lib/target_ownership.js`, `src/lib/retention.js`, `src/controllers/target_controllers.js`, `src/routes/target_routes.js`, `src/validators/target_validator.js`
- Alterados: `prisma/schema.prisma`, `src/controllers/scan_controllers.js`, `src/validators/scan_validator.js`, `src/lib/audit_log.js`, `src/lib/privacity.js`, `src/lib/py/security_engine_client.js`, `src/middlewares/rate_limit_middleware.js`, `src/server.js`, `src/py/security_engine/app/{schemas,main,zap_runner,nuclei_runner}.py`

## 6. Como foi validado
- **Node, 49 testes** (`npm test`):
  - os três métodos de verificação;
  - escopo de domínio × host (`exemplo.com` cobre `www.exemplo.com`, mas não `exemplo.com.evil.net`);
  - anti-SSRF e redirecionamento recusado;
  - bloqueio sem alvo verificado;
  - prova removida derruba a verificação;
  - passivo sem opt-in × ativo com opt-in registrado;
  - auditoria e retenção.
- **Python, 16 testes** (`npm run test:engine`): política de ataque ativo, throttling e bloqueio de DoS.
- **Teste de mutação:** com a exigência de verificação desligada de propósito, 6 testes falham. Restaurada, os 49 passam.
- **Boot real:** o servidor sobe com as rotas novas e elas exigem login (401 sem cookie).
- **Não validado ainda:** verificação contra um domínio real e uma varredura real com o ZAP.

## 7. Limitações e riscos conhecidos
- O front-end ainda não tem a tela de verificação: o cadastro de varredura do dashboard recebe 403 para sites públicos até a etapa do front.
- A propagação de DNS pode levar minutos: **verificar o domínio da demonstração antes do dia da apresentação** e manter a prova publicada.
- Throttling aplicado só em produção. Homologação com opt-in usa a velocidade padrão do ZAP.
- As declarações do opt-in precisam de texto revisado pela orientadora ou por um advogado antes de uso real.

## 8. Para os slides
- **Problema ético-legal:** uma ferramenta de pentest pode virar arma. Testar sistema alheio sem autorização é crime (art. 154-A do CP).
- **Solução:** prova técnica de propriedade (DNS, arquivo ou meta tag), igual à usada pelo Google, conferida de novo a cada varredura.
- **Ataque real só com consentimento explícito** a cada execução: autorização do titular + permissão do provedor de hospedagem, registradas com data, hora e IP.
- **Não derrubar o site do cliente:** throttling em produção e bloqueio de templates de negação de serviço.
- **Conformidade:** trilha de auditoria por 6 meses (Marco Civil) e eliminação automática depois (LGPD).
