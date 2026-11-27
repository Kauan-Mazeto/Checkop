# 19 — Ajuda por IA (perguntas sobre uma varredura ou análise de código)

**Data:** 2026-11-27 · **Status:** Implementado (compila); chamada real à IA pendente de teste · **Requisitos:** RF-11, LGPD art. 6º, VI (transparência) e art. 9º

## 1. Problema
A IA só aparecia na correção de código. Não dava para perguntar coisas como:
- "o que corrijo primeiro?";
- "isto é falso positivo?";
- "explica essa falha".

Essas perguntas servem para qualquer perfil, sobre uma varredura ou sobre uma análise de código.

## 2. Proposta
Uma tela nova no menu lateral, **"Ajuda por IA"**, com quatro passos:
1. a pessoa escolhe uma varredura ou uma análise de código;
2. vê **exatamente** o que será enviado;
3. confirma;
4. pergunta.

Cada pergunta usa **1 crédito de IA**, devolvido se a resposta falhar. A conversa **não é gravada**.

**Fora do escopo:** guardar conversas; enviar código-fonte ou evidências técnicas; resposta em streaming (a resposta chega inteira).

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Modo de oferta | grátis no Premium · com créditos · não fazer | **com aviso e créditos** (escolha do usuário); usa os créditos que já existem |
| Quem monta o contexto | o navegador · o servidor | **o servidor**, a partir do banco e só com itens do próprio usuário. A prévia (`GET /context`) é o mesmo texto enviado à Anthropic |
| O que vai de uma varredura | o achado inteiro · sem evidências | título, severidade, ferramenta, status, CVE/CVSS, descrição e recomendação, e o **endereço da página sem a query string**, porque a query string traz a carga de teste. **Nunca** vão `rawRequest`, `rawResponse`, `attack`, `reproduction` e `detection` |
| Tamanho do contexto | todos os achados · limite | a mesma falha em várias URLs vira **um grupo** (até 3 locais); vão até 40 falhas, **as em aberto primeiro** e depois pela severidade; textos com até 500 caracteres. O que ficou de fora é dito no próprio contexto |
| Guardar a conversa | servidor · navegador · não guardar | **não guardar**: some ao sair da tela. No log de auditoria fica só `AI_HELP_ASKED`, com o item e os créditos, sem o texto |
| Modelo e chamada | — | `claude-opus-5-5` (o mesmo `AI_FIX_MODEL` da correção), `effort: medium`, prompt de sistema fixo com cache e `fallbacks: "default"` para recusas; trata `refusal` e `max_tokens` |

## 4. O que foi implementado
**Backend**
- `src/lib/ai_help.js`:
  - `scanContextText` e `codeContextText` montam o contexto;
  - `pageOf` tira a query string do endereço;
  - `loadContext` busca o item no banco, filtrando pelo usuário;
  - `answerQuestion` faz a chamada pelo SDK da Anthropic. O contexto vai entre `<contexto>` e o prompt manda tratá-lo como dado, nunca como instrução.
- `src/controllers/ai_help_controllers.js`:
  - `GET /api/ai-help/sources`: varreduras concluídas, análises e créditos;
  - `GET /api/ai-help/context`: a prévia;
  - `POST /api/ai-help/chat`: debita o crédito de forma atômica antes da chamada e devolve se a IA falhar.
- `src/validators/ai_help_validator.js`: até 20 falas, alternando entre usuário e IA, terminando com uma pergunta de até 2.000 caracteres.
- `src/routes/ai_help_routes.js`: Premium, com o mesmo limite por hora da correção com IA.
- `src/server.js`: `/api/ai-help` com tempo limite de 3 min e corpo de até 300 kb.
- `src/lib/audit_log.js`: ação `AI_HELP_ASKED`.
- `src/lib/privacity.js` (2.3): itens 2.5 (novo: o que é enviado e o que não é), 4 (Anthropic) e 6 (retenção).
- `src/lib/terms_of_use.js` (2.2): itens 4.4 (crédito por pergunta) e 7.4.

**Front-end**
- `core/services/ai-help.service.ts` e `shared/ui/chat-markdown.ts`. O markdown da resposta vira elementos pelo template, sem `innerHTML`.
- `pages/ai-help-page/`: tela com:
  - a escolha entre varreduras e análises;
  - o saldo e a compra de créditos;
  - a prévia aberta até a pessoa marcar "Entendi";
  - sugestões de pergunta por tipo (e uma própria para o Estudante);
  - a conversa, com "Nova conversa".
- Menu lateral (`app-shell`): "Ajuda por IA" em Segurança, com o selo PRO no Free.
- Atalhos "Perguntar à IA" no detalhe da varredura e no resultado da análise de código (`/ai-help?kind=...&id=...`).

## 5. Como foi validado
- `ng build`: sem erros.
- **Contexto real** de uma varredura do banco local, com 380 achados:
  - os achados viraram 67 falhas distintas;
  - foram as 40 primeiras, as em aberto antes;
  - o texto ficou com cerca de 27 mil caracteres;
  - nenhuma carga de teste (`<svg onload…>`) aparece no endereço.
- **Script de conferência:**
  - o contexto da análise de código não tem código;
  - outro usuário recebe "não encontrado";
  - o validador recusa uma conversa que começa pela IA.
- **Pendente:** uma pergunta real à IA. Ela gasta crédito da API da Anthropic e precisa de `ANTHROPIC_API_KEY` no `.env`.

## 6. Limitações e riscos conhecidos
- A resposta pode levar de 10 a 40 s, sem streaming. A tela mostra "Pensando…".
- Cada pergunta reenvia o contexto e a conversa. O cache do prompt de sistema ajuda, mas conversas longas custam mais (limite de 20 falas).
- As descrições do Nuclei e do ZAP estão em inglês no banco. A IA responde em português, mas a prévia mostra o texto original.

## 7. Para os slides
- Ajuda por IA: perguntas sobre uma varredura ou análise, para qualquer perfil.
- Transparência: a tela mostra o texto exato que vai para a IA antes do primeiro envio.
- Privacidade: sem código, sem evidências e sem carga de teste; a conversa não é guardada.
- Créditos: 1 por pergunta, devolvido automaticamente se a IA falhar.
