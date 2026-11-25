# 10 — Novo aceite dos Termos e "Baixar meus dados"

**Data:** 2026-11-22 · **Status:** Implementado e testado · **Requisitos:** LGPD art. 18, II e V (acesso e portabilidade) e art. 19, § 2º; Termos de Uso, seção 14

## 1. Problema
**Termos.** A versão aceita era gravada no cadastro, mas:
- havia **um registro por usuário** (`TermsAcceptance.userId` único), então não existia onde gravar o aceite de uma versão nova;
- nada comparava a versão aceita com a atual. Quando os Termos mudavam, o usuário seguia usando sob a versão antiga sem ser avisado, apesar de a seção 14 dos Termos prever novo aceite.

**Dados pessoais.** A tela "Conta e privacidade" só indicava um e-mail para pedir acesso ou portabilidade dos dados. O direito existia no papel, mas não no produto.

## 2. Proposta
- Guardar o **histórico de aceites**: um registro por versão aceita.
- Comparar o aceite mais recente com `TERMS_OF_USE.version`. Se for diferente, pedir o novo aceite e bloquear o uso da plataforma até lá.
- Botão **"Baixar meus dados"**: um JSON com tudo o que a conta guarda, para qualquer plano.

Fora do escopo: aviso por e-mail quando os Termos mudam e tela mostrando o que mudou entre as versões.

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Como gravar o novo aceite | Sobrescrever o registro; histórico | **Histórico**: o aceite serve de prova (quem aceitou qual versão, quando, de qual IP). Sobrescrever apagaria a prova do aceite anterior. |
| Quando a versão "mudou" | Comparar números; qualquer diferença | **Qualquer diferença** do aceite mais recente com a versão atual. Conta sem aceite nenhum (criada antes da regra B7) também precisa aceitar. Convenção já existente em `terms_of_use.js`: alteração relevante → sobe a versão. |
| Onde bloquear | Só no front; no backend | **Nos dois.** O `auth_middleware` responde 403 `TERMS_UPDATE_REQUIRED` para alvos, varreduras, análise de código e admin. O front mostra uma janela que cobre as telas logadas. Só o front seria fácil de contornar chamando a API direto. |
| O que continua liberado sem o novo aceite | Nada; só sair; cuidar da conta | **Tudo em `/api/auth` e `/api/privacy`**: ver a sessão, aceitar, baixar os dados, excluir a conta, trocar preferências e sair. Quem não concorda com os Termos novos não pode perder os direitos da LGPD (acesso, portabilidade, eliminação). Na tela "Conta e privacidade", a janela vira um aviso no topo. |
| Formato do "Baixar meus dados" | PDF; CSV; JSON | **JSON**: formato "que favoreça o uso" e possa ir para outro fornecedor (art. 19, § 2º), e guarda a estrutura (varreduras com seus achados). |
| O que fica de fora do arquivo | Nada; segredos | **Só segredos de autenticação** (hash da senha, códigos de redefinição, versão do token, contadores de bloqueio) e o token de verificação de domínio, que não são dados sobre a pessoa. A conta é lida com lista fechada de campos: um campo novo no banco não entra por acidente. |
| Limite | Sem limite; por hora | **5 por hora**: a exportação junta varreduras e achados e pode ser pesada. |

## 4. O que foi implementado
**Backend**
- [schema.prisma](../../../prisma/schema.prisma) + migration `20261122000000_historico_de_aceite_dos_termos`: `TermsAcceptance.userId` deixa de ser único; índice `(userId, acceptedAt)`; relação `User.termsAcceptances`.
- [terms_status.js](../../../src/lib/terms_status.js) (novo): `latestTermsAcceptance`, `termsStatus`, `recordTermsAcceptance`, `termsUpdateRequiredBody`.
- [auth_middleware.js](../../../src/middlewares/auth_middleware.js): calcula `req.termsStatus` e bloqueia com 403 `TERMS_UPDATE_REQUIRED` fora de `/api/auth` e `/api/privacy`.
- [auth_routes.js](../../../src/routes/auth_routes.js): `GET /me` devolve `terms`; `POST /api/auth/terms/accept` (`{ accepted: true }`); `GET /api/auth/my-data` (limite de 5 por hora).
- [auth_controllers.js](../../../src/controllers/auth_controllers.js): `acceptTerms` e `exportMyData`. Cadastro e login com Google passam a usar `recordTermsAcceptance`.
- [audit_log.js](../../../src/lib/audit_log.js): ações `TERMS_ACCEPTED` e `DATA_EXPORTED`.
- [privacity.js](../../../src/lib/privacity.js): seção 9 descreve o "Baixar meus dados" (versão 2.2). Os Termos continuam na 2.1, então ninguém precisa aceitar de novo por causa desta alteração.

**Front-end**
- [app-shell.component.ts](../../../../front-end/src/app/shared/components/app-shell/app-shell.component.ts): janela "Os Termos de Uso foram atualizados", com a versão aceita e a nova, link para ler, caixa "Li e aceito", "Aceitar e continuar", "Sair" e atalho para Conta e privacidade. Nessa tela, vira um aviso no topo com "Revisar e aceitar".
- [auth.guard.ts](../../../../front-end/src/app/core/guards/auth.guard.ts): guarda a situação dos Termos que vem do `/me` a cada navegação.
- [account-page](../../../../front-end/src/app/pages/account-page/account-page.component.html): cartão "Baixar meus dados" com a lista do que entra e do que fica de fora.
- [account.service.ts](../../../../front-end/src/app/core/services/account.service.ts): `acceptTerms()` e `downloadMyData()`.

## 5. Como foi validado
**Testes automatizados**
- `npm test` (backend): 169 OK. São 9 novos em [terms_and_my_data.test.js](../../../src/tests/terms_and_my_data.test.js): em dia segue normal; versão antiga → 403 em scans, targets, sast e admin; conta sem aceite também precisa aceitar; `/api/auth` continua liberado; aceitar grava registro novo com versão, IP e navegador e libera a plataforma; aceitar de novo não duplica; aceite precisa ser explícito; o arquivo de dados tem todas as seções e vem em anexo; tudo filtrado pelo próprio usuário e sem segredos.
- `npm run test:ci` (front): 76 OK. São 4 novos em `app-shell.component.spec.ts`: sem janela com os Termos em dia; janela com as versões e botão travado até marcar a caixa; aceitar chama a API e fecha; em Conta e privacidade vira aviso que reabre a janela.

**De ponta a ponta no Docker (API via nginx, conta descartável excluída no fim)**

| Passo | Resultado |
|---|---|
| Cadastro → `/me` | `acceptedVersion 2.1`, `updateRequired false` |
| Aceite trocado para `2.0` no banco → `/me` | `updateRequired true` |
| `GET /api/scans` | 403 `TERMS_UPDATE_REQUIRED` |
| `GET /api/auth/my-data` (ainda desatualizado) | 200, anexo `checkop-meus-dados-AAAA-MM-DD.json`, 7 seções, nenhum hash, senha ou código no arquivo |
| Aceitar com `accepted: false` | 400 "É necessário aceitar os Termos de Uso para continuar." |
| Aceitar com `accepted: true` → `GET /api/scans` | 200 |
| Histórico no arquivo de dados | aceites `['2.0', '2.1']`; auditoria `DATA_EXPORTED`, `TERMS_ACCEPTED` |

A migration foi aplicada no banco do Docker na subida do backend (`prisma migrate deploy`).

**Como ver a janela no app:** suba `TERMS_OF_USE.version` em `backend/src/lib/terms_of_use.js` (ex.: `2.2`) e entre com qualquer conta.

## 6. Limitações e riscos conhecidos
- A mudança é percebida na próxima navegação (o guard consulta o `/me`). Quem está no meio de uma tela recebe o 403 com a mensagem explicando, e a janela aparece ao trocar de página.
- O arquivo não traz o código enviado para análise, porque ele não é guardado. Também não traz o que fica com a Anthropic na correção com IA, que segue a política de retenção dela.
- Pedidos de correção de dados continuam pelo e-mail de privacidade, que ainda é provisório.

## 7. Para os slides
- Termos mudaram → o usuário é avisado e precisa aceitar de novo. Cada aceite fica no histórico (versão, data, IP), como prova.
- O bloqueio vale no servidor, não só na tela. Mesmo sem aceitar, o usuário pode baixar os dados e excluir a conta.
- "Baixar meus dados": portabilidade da LGPD (art. 18) em um clique, num JSON legível por máquina e sem segredos de autenticação.
