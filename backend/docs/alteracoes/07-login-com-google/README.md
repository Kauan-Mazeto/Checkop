# 07 — Login com Google (RF-03)

**Data:** 2026-11-16 · **Status:** Implementado e testado · **Requisitos:** RF-03, RF-05, RNF-07, RNF-10

## 1. Problema
O backend já validava o login com Google desde a correção [B7](../02-correcoes-de-seguranca/README.md): confere o token no servidor, exige e-mail verificado e pede o aceite dos termos no primeiro acesso. Mesmo assim, o botão "Continuar com Google" no login e no cadastro não fazia nada.

Faltavam também quatro coisas:
- **Perfil:** quem entrava pelo Google ficava sempre com o perfil Dev, sem escolher.
- **Limite de tentativas:** a rota `/api/auth/google` não tinha nenhum.
- **Erro de configuração:** sem `GOOGLE_CLIENT_ID`, o erro devolvido era "token inválido", o que confunde.
- **Abordagem da branch `front`:** o Kauan usava o One Tap (`google.prompt()`), que o Google deixa de mostrar depois que o usuário fecha a janela uma vez.

## 2. Proposta
Usar o botão oficial do Google Identity Services (`renderButton`) no login e no cadastro. Concluir o primeiro acesso na própria tela, com o aceite dos termos e a escolha do perfil, igual ao cadastro por e-mail.

**Fora do escopo:** login com outros provedores.

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Tipo de botão | One Tap (`prompt`) · botão oficial | **Botão oficial.** O One Tap é suprimido pelo Google depois de ser fechado e falha calado. |
| Onde fica o client id | `environment.ts` do front · `.env` do backend | **`.env` do backend**, exposto em `GET /api/auth/google/config`. O client id é público e assim fica uma fonte única, sem rebuild do front. |
| Perfil no primeiro acesso | Padrão Dev · escolher | **Escolher**, no mesmo passo do aceite dos termos (RF-05). Só vale na criação: quem já tem conta mantém o perfil. |
| Limite de tentativas | Reusar o do login · próprio | **Próprio** (20 a cada 15 min). O primeiro acesso faz duas chamadas e não deve gastar a cota do login por senha. |

## 4. O que foi implementado
**Backend**
- `GET /api/auth/google/config` devolve `{ enabled, clientId }`.
- Sem `GOOGLE_CLIENT_ID`, `POST /api/auth/google` responde 503 com o código `GOOGLE_NOT_CONFIGURED`.
- `role` é opcional no `googleLoginSchema` (não aceita ADM) e é aplicado só na criação da conta.
- `googleLoginLimiter` protege a rota.

**Front-end**
- `core/services/google-auth.service.ts` carrega o script do Google uma vez e desenha o botão oficial (tema escuro, em português).
- `shared/components/google-sign-in` é o botão mais o primeiro acesso:
  1. Em `TERMS_REQUIRED`, mostra o nome e o e-mail da conta Google, a escolha do perfil e o aceite dos termos.
  2. Depois reenvia o mesmo token com essas informações.
- Login e cadastro usam o componente. O divisor "ou entre com e-mail" só aparece quando o Google está configurado.
- Ao sair, `disableAutoSelect()` impede o Google de entrar sozinho na mesma conta.

## 5. Como foi validado
- **Backend:** `npm test` passa com 95 testes. Os novos cobrem a rota de configuração, o servidor sem client id (503 sem criar conta), o perfil escolhido na conta nova, que o perfil não muda numa conta existente e que o schema recusa ADM.
- **Front:** `ng build` passa e `npm run test:ci` passa com 55 testes. Os novos cobrem a leitura do nome e do e-mail do token (com acentos), o botão oculto sem configuração, a entrada direta e o primeiro acesso, em que sem aceite não continua e o reenvio leva o token, o aceite e o perfil.
- **API real:** `/api/auth/google/config` devolve o client id do `.env` e um token falso é recusado com 401.
- **Não validado:** o clique real na janela do Google, que depende do projeto no Google Cloud (ver seção 6).

## 6. Limitações e riscos conhecidos
- **Configuração no Google Cloud Console.** No client OAuth (tipo "Aplicativo da Web"), as *Origens JavaScript autorizadas* precisam ter `http://localhost:4200`, `http://localhost` e, na apresentação, o domínio real. Sem isso, o Google recusa abrir a janela.
- Se a tela de consentimento OAuth estiver em modo **Teste**, só os e-mails cadastrados como "usuários de teste" conseguem entrar.
- Uma conta com senha e o mesmo e-mail é **vinculada** ao Google no primeiro login. É seguro porque o Google só envia `email_verified` quando a pessoa comprovou o e-mail.

## 7. Para os slides
- Login social (RF-03) com o botão oficial do Google. A senha nunca passa pelo Checkop.
- O token é conferido no servidor: assinatura, client id e e-mail verificado.
- O primeiro acesso pelo Google também exige o aceite dos termos (LGPD) e a escolha do perfil.
