# 05 — Front-end: fluxo real de varredura, resultados e gráficos

**Data:** 2026-11-09 · **Status:** Implementado e testado · **Requisitos:** RF-11, RF-12 (JSON), RF-13, RF-25 (parcial), espec.txt seções 2 e 3, TCC seção 7.1 (Chart.js)

## 1. Problema
- O dashboard só **cadastrava** varreduras: não escolhia o objetivo, não executava e não mostrava resultado.
- Não havia tela para a verificação de domínio ([03](../03-verificacao-de-dominio/README.md)) nem para os 24 objetivos ([04](../04-objetivos-de-varredura/README.md)).
- Faltavam os gráficos previstos na proposta (Chart.js) e a apresentação de resultados do `espec.txt`: card de status, veredito, PoC, compliance e visualizador de código.
- **O build de produção já falhava** (SCSS das páginas acima do limite de 8 kB) e **os testes do front nem compilavam** (spec antigo testava token no `localStorage`, que o projeto não usa mais).

## 2. Proposta e escopo
Construir todas as telas logadas, do dashboard em diante, seguindo o design existente.

**Fora do escopo:**
- landing, login e cadastro, que ficaram intactos a pedido da equipe;
- login com Google;
- exportação em PDF;
- planos Free/Premium, fora do escopo pelo TCC 6.3.

## 3. Telas
| Rota | Tela | Destaques |
|---|---|---|
| `/dashboard` | Painel | 4 indicadores reais; **4 gráficos** (severidade em rosca, linha dos últimos 30 dias, OWASP Top 10, por ferramenta); varreduras recentes clicáveis; bloco por perfil (RF-11): QA relatórios, DEV alertas, Pentester logs, Estudante trilha |
| `/targets` | Alvos | Cadastro com os 3 métodos explicados; instruções com botão **Copiar**; **Verificar agora**; status verificado/pendente; aviso legal (art. 154-A) |
| `/scans/new` | Nova varredura | URL; **seletor dos 24 objetivos** agrupados em 6 categorias, com descrição, OWASP, selo "exige ataque" e "cobertura parcial"; declaração de autorização; em `TARGET_NOT_VERIFIED`, atalho para verificar o domínio com a URL preenchida |
| `/scans/:id` | Detalhe | **Execução:** AJAX spider, login de teste e o **opt-in de ataque** com as duas declarações (o botão só libera com ambas). **Andamento:** acompanhamento automático a cada 5 s, com cronômetro. **Resultado:** card de veredito com contagem por severidade, avisos dos motores, aviso de Modo Seguro, 4 abas (Resumo com gráficos · Achados com filtro e detalhes · Evidências/PoC · Compliance LGPD/PCI) e **Exportar JSON** |
| `/code-analysis` | Análise de código (SAST) | Colar código ou enviar arquivos; **visualizador estilo IDE** com a linha vulnerável em vermelho; lado a lado "código inseguro × como corrigir"; gráfico por severidade |

Todas as rotas logadas têm **guard de autenticação** (confirma a sessão no backend via `/api/auth/me`) e são **carregadas sob demanda**: o Chart.js não entra no bundle da landing.

### Correspondência com o espec.txt
| espec.txt | Onde está |
|---|---|
| 2.2 Card de status com badge colorido (🔴/🟡/🔵) e veredito | Card de veredito no detalhe |
| 2.2 Descrição da falha em linguagem universal | Achados → "Descrição" e, para o perfil Estudante, "Entenda a falha" |
| 3.1 PoC: payload injetado, evidência da resposta, parâmetro exato | Aba Evidências / PoC (oculta em Modo Seguro, RF-08) |
| 3.2 Visualizador de código, linha crítica destacada, correção lado a lado | Tela de Análise de código |
| 3.3 Painel de conformidade LGPD / PCI-DSS | Aba Compliance, agrupada por lei + artigo, com os achados que disparam cada item |
| "melhore a apresentação, gráficos" | 4 gráficos no dashboard, 3 no detalhe e 1 no SAST |

## 4. Decisões tomadas
| Decisão | Opções | Escolha e motivo |
|---|---|---|
| Biblioteca de gráficos | Chart.js + ng2-charts · Chart.js direto · CSS | **Chart.js direto** (4.5.1, versão fixa) com um componente próprio. A biblioteca é a da proposta (7.1); o ng2-charts exigiria também o `@angular/cdk` |
| Estilo das telas novas | Copiar tokens em cada tela (padrão antigo) · arquivo compartilhado | **Compartilhado** em `src/styles/_app-ui.scss`, sob a classe `.ck-app`: mesmos tokens e classes, sem vazar para landing/login/cadastro |
| Build de produção quebrado | Refatorar estilos antigos · aumentar limite | **Aumentar o limite** por componente (aviso 16 kB, erro 32 kB). Não mexe nas telas que não eram do escopo |
| Código corrigido no SAST | Gerar com IA · orientação textual | **Orientação textual.** O motor devolve a sugestão de correção, não o código corrigido |
| Planos Free/Premium | Implementar paywall · mostrar tudo | **Mostrar tudo.** Cobrança está fora do escopo do TCC (6.3); o que esconde dados é o Modo Seguro |

## 5. Arquivos
- **Base:** `core/http/api-error.ts` (erro com `code`), `core/guards/auth.guard.ts`, `core/services/{scan,target,sast}.service.ts`
- **Compartilhado:** `shared/components/app-shell` (topbar e navegação), `shared/components/chart` (Chart.js), `shared/ui/{labels,chart-data}.ts`, `src/styles/_app-ui.scss`
- **Telas:** `pages/Dashboard-page` (reescrita), `pages/targets-page`, `pages/new-scan-page`, `pages/scan-detail-page`, `pages/code-analysis-page`
- **Config:** `app.routes.ts`, `angular.json` (limite de estilo), `package.json` (chart.js, script `test:ci`)
- **Backend:** `GET /api/scans` passa a devolver `objective`, `objectiveLabel` e `findingsCount`
- **Bug corrigido:** o `templateUrl` do dashboard apontava para `dashboard-page.component.html` (minúsculo) e o arquivo é `Dashboard-page...`. No Windows funciona; num servidor Linux o build quebraria.

## 6. Como foi validado
- `ng build` (produção) **passa**. Bundle inicial em 459 kB (era 731 kB antes do carregamento sob demanda). Sobra só o aviso do SCSS da landing, que não foi tocada.
- **31 testes do front** (`npm run test:ci`, Edge headless):
  - serviços: corpo das requisições, cookie, `code` do erro, mensagens;
  - dados dos gráficos;
  - lógica do detalhe: ordenação, filtro, compliance, exportação, cronômetro;
  - agrupamento de objetivos;
  - visualizador de código;
  - componente de detalhe: botão bloqueado sem as duas declarações, localhost sem opt-in, resultado com veredito e abas, acompanhamento automático.
- **Teste de mutação:** com a trava do opt-in desligada de propósito, 1 teste falha. Restaurada, os 31 passam.
- **Integração:** `ng serve` + backend reais. As rotas novas respondem 200 e o proxy `/api` chega ao backend (401 nas rotas protegidas sem login, 200 na pública).
- **Backend:** 64 testes continuam passando.
- **Não validado:** clique a clique num navegador com usuário logado e varredura real com o ZAP. Fica para o ensaio da demonstração.

Para rodar os testes do front no Windows sem Chrome:
```bash
set CHROME_BIN=C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
npm run test:ci
```

## 7. Limitações e riscos conhecidos
- **Conflito de porta na demo:** o backend usa `PORT=8080`, que também é a porta padrão da API do ZAP. Rode o ZAP em outra porta (ex.: 8090) e defina `ZAP_API_URL=http://localhost:8090` no motor Python.
- O botão "Continuar com Google" do login continua sem função (fora do escopo desta etapa).
- O RF-11 ficou parcial: o painel muda o bloco por perfil e o Estudante recebe explicações, mas o backend ainda não filtra o conteúdo por perfil.
- A exportação é só em JSON; PDF (RF-12) continua pendente.
- A análise de código não é salva no histórico (o backend não persiste o SAST).

## 8. Para os slides
- **Fluxo completo na tela:** verificar domínio → escolher o tipo de falha → autorizar → acompanhar → ver o resultado.
- **Gráficos** (Chart.js, como previsto na proposta): severidade, tendência de 30 dias, OWASP Top 10 e ferramentas.
- **Resultado em camadas:** veredito simples para qualquer pessoa; evidência técnica (PoC) para quem testa; compliance LGPD/PCI para a gestão.
- **Ética na interface:** o botão de ataque só libera com as duas declarações, e a tela explica o porquê (art. 154-A).
- **Análise de código** estilo IDE, com a linha vulnerável destacada e a correção ao lado.
