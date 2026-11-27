# 13 — Novo visual da landing, do login e do cadastro

**Data:** 2026-11-26 · **Status:** Implementado (compila; sem testes novos) · **Requisitos:** RF-01, RF-02, RF-03, RF-05

## 1. Problema
As três telas públicas tinham outro visual (terminal, "scanline", anéis de estatística) e números que não batiam com o produto: "14 vetores", "<5s scan time", "5 scans/mês". Uma varredura completa leva minutos, e o Free é 1 varredura por dia. A landing ainda carregava um "dashboard de demonstração" inteiro, com dados falsos e modal de scan simulado, que nunca aparecia na tela. Cada tela tinha um SCSS próprio de 600 a 1.500 linhas, quase todo repetido.

## 2. Proposta
Aplicar o visual aprovado no canvas "Checkop — direções de design", página **Landing e acesso**, com textos tirados do que o produto realmente faz. A lógica das telas não muda (login, Google, rascunho do cadastro, validações, troca para Premium).

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Onde fica o estilo | Um SCSS por tela; arquivo global escopado | `src/styles/_public-ui.scss`, escopado em `.pub`, no mesmo padrão do `_app-ui.scss` das telas logadas. As telas só guardam o próprio layout. |
| Fonte | Google Fonts (Inter); fonte do sistema | Fonte do sistema, com Inter só se já estiver instalada. Nenhuma requisição a terceiros antes do login (LGPD) e sem depender de internet. |
| Cor dos botões | `#E5484D` da marca; tom mais escuro | `#D63A40` no fundo dos botões: texto branco com contraste 4,6:1. O `#E5484D` dá 3,9:1, abaixo do mínimo. O `#E5484D` continua nos destaques de texto. |
| Números da landing | Manter; trocar por fatos | Fatos do produto: limite do Free, etapas, ferramentas e planos de `plans.ts`. |
| Sintaxe dos templates | `*ngIf`/`*ngFor`; `@if`/`@for` | `@if`/`@for`. O Angular do projeto já marca `*ngIf` como obsoleto. |

## 4. O que foi implementado
- `front-end/src/styles/_public-ui.scss` (novo) e `styles.scss` (`@use`): cores, botões, campos, erro, divisor, layout de login/cadastro e cartões selecionáveis. Também define `--primary`, `--surface` etc., que o `app-google-sign-in` lê.
- **Landing** (`landing-page.component.*`):
  - **Conteúdo:** topo com a prévia de um resultado (achados reais do laboratório), "Como funciona" em 6 etapas, local/homologação × produção, as 8 ferramentas, os 4 perfis, os planos de `PLAN_CARDS`, chamada final e rodapé (equipe, contatos, GitHub e o aviso do art. 154-A, mantidos).
  - **Removido:** o dashboard de demonstração e o seletor antigo `app-shieldtest`, que passou a ser `app-landing-page`.
  - **Navegação:** a barra do topo fica fixa e as âncoras compensam a altura dela.
- **Login** (`login-page.component.html/.scss`): marca e três pontos fortes à esquerda; à direita o Google, e-mail e senha com mostrar/ocultar.
- **Cadastro** (`register-page.component.*`):
  - **Passos:** Conta → Perfil → Plano, clicáveis no lado da marca, com barra de progresso.
  - **Escolhas:** cartões de perfil e de plano com `role="radio"`; o Enterprise aparece desabilitado.
  - **No `.ts`:** só ganharam uma descrição curta (`hint`) cada perfil e cada passo.
- **Telas estreitas (≤ 900 px):** o lado da marca some e aparece "Voltar para o site".

## 5. Como foi validado
- `ng build --configuration development`: compilou sem erros.
- Não foram escritos nem rodados testes (ver preferência do projeto). Falta conferir as três telas no navegador, inclusive no celular.

## 6. Limitações e riscos conhecidos
- O selo "Mais popular" do Premium vem de `plans.ts`; sem usuários reais, vale trocar por algo verificável.
- Os contatos do rodapé (`contato@`/`suporte@checkop.com.br`) ainda são provisórios.
- "Esqueceu a senha?" continua sem ação (já era assim).

## 7. Para os slides
- Landing, login e cadastro com o mesmo visual do produto logado.
- A landing só afirma o que o Checkop faz de verdade: nada de números inventados.
- Acessibilidade: contraste mínimo nos botões, foco visível, rótulos e grupos de escolha acessíveis por teclado.
- Menos código: um estilo compartilhado no lugar de três SCSS repetidos.
