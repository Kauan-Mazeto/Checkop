# 17 — Painel em abas e gráficos para QA e Pentester

**Data:** 2026-11-26 · **Status:** Implementado (compila; falta conferir na tela) · **Requisitos:** RF-11 (painel por perfil), RF-13 (histórico)

## 1. Problema
- **Painel longo:** uma coluna só empilhava indicadores, bento, atalhos, painel do perfil e planos; era preciso rolar muito.
- **Visual pesado:** cada bloco tinha contorno branco grosso, e os painéis de perfil eram cartões dentro de cartões ("muitos retângulos").
- **Poucos gráficos no QA e no Pentester:** quase tudo era lista ou barra de texto.
- **Dados sem uso:** o backend já mandava status de triagem, achados por ferramenta e a linha do tempo dos 30 dias, e nada disso aparecia.

## 2. Proposta
Inspirada em painéis como os do Vercel, Linear e Datadog:
- **Abas** (Visão geral · Painel do perfil · Seu plano), cada uma cabendo numa tela.
- **Blocos planos:** borda de 1px sutil, sem contorno branco e sem cartão dentro de cartão.
- **Gráficos por perfil** com os dados que já existem (sem mudar o backend).

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Menos rolagem | Encolher tudo; abas | Abas: cada parte cabe numa tela e o perfil continua a um clique. A aba aberta é lembrada no navegador (só conveniência). |
| Atalhos | Manter; tirar | Tirar: repetiam o menu lateral e o botão "Nova varredura" do topo. |
| Gráficos do QA | — | **Status da correção** (abertos × corrigidos × falso positivo × ignorados), **tipos mais frequentes** e **evolução por URL** (achados em cada execução da mesma URL: mostra regressão). É o que o QA acompanha: o que foi resolvido e o que voltou. |
| Gráficos do Pentester | — | **Nota CVSS** por faixa oficial (FIRST), **confiança** (o que precisa de confirmação manual), **endpoints com mais achados** (superfície de ataque) e **por ferramenta**. É onde está o risco e por onde atacar. |
| Log técnico | Sempre aberto; recolhido | Recolhido: é consulta eventual e ocupava meia tela. |

## 4. O que foi implementado
- `shared/ui/chart-data.ts`:
  - funções novas: `triageDoughnut`, `targetTrendLine`, `cvssHistogram`, `confidenceDoughnut`, `endpointsBar`, `endpointOf`;
  - opções novas: `LINE_LEGEND_OPTIONS` e `COLUMN_OPTIONS`.
- `pages/Dashboard-page`:
  - abas (`view`, lembrada em `localStorage` com try/catch);
  - visão geral com o gráfico novo "Últimos 30 dias" (linha do tempo que o backend já mandava);
  - estatísticas (`stats`) passadas aos painéis de QA e Pentester;
  - sem contorno branco.
- `role-panels.ts`: painéis de QA e Pentester refeitos com `.dash-grid`/`.dash-tile`.
- `styles/_app-ui.scss`: `.dash-grid`, `.dash-tile`, `.dash-tile-head` e `.dash-note`, compartilhados entre o painel e os componentes de perfil.

### 4.1 Segunda rodada: mais abas de relatório e o fim do contorno branco
- **Abas novas**, ficando seis no total: Visão geral · **Riscos** · **Varreduras** · **Alvos** · Painel do perfil · Seu plano (`report-tabs.ts`).
  - **Riscos:** "Corrigir primeiro" (as 8 falhas abertas mais graves, cada uma abrindo a sua varredura), status da correção, nota CVSS, confiança e tipos mais frequentes.
  - **Varreduras:** por status (com % de sucesso), por ambiente, achados por ferramenta, varreduras por dia (30 dias), tipos de teste usados e duração média por tipo.
  - **Alvos:** tabela dos sites (ambiente, varreduras, última, achados, diferença para a anterior do mesmo teste), achados por site, endpoints com mais achados e evolução por site.
- **Painel de QA:** "Evolução por URL" saiu (estava repetida na aba Alvos). No lugar entrou **Evolução das correções**: uma barra por varredura recente com corrigidos, descartados (falso positivo/ignorado) e abertos empilhados (`triageRunOf`, `triageEvolutionBar`).
- **Comparação justa:** a evolução por site e a coluna "vs. anterior" só comparam o **mesmo tipo de teste no mesmo site**, e só varreduras concluídas. Antes, misturar "Varredura completa" com "só SQL Injection" mostrava quedas falsas (88 → 1 → 69).
- **Contorno branco removido em todas as telas** (Conta, Nova varredura, Planos, Detalhe, Histórico, Domínios e estilos globais):
  - blocos com borda sutil (`rgba(255,255,255,0.08)`);
  - campos, selects e buscas com uma borda mais visível (`0.32`), para o limite do campo continuar legível;
  - o anel de foco do teclado continua branco (acessibilidade).

### 4.2 Terceira rodada: cada perfil vê só o que serve para ele
As abas de relatório eram iguais para todos. Agora as abas e os blocos dependem do perfil (`TABS_BY_ROLE` em `Dashboard-page.component.ts`, `REPORT_TILES` em `report-tabs.ts`):

| Perfil | Abas | Blocos próprios |
|---|---|---|
| QA | Visão geral · Riscos · Varreduras · Alvos · Painel · Plano | corrigir primeiro, status da correção, confiança, tipos; status/tipos de teste/duração das varreduras; evolução por site; no painel: relatórios e **evolução das correções** |
| Pentester | Visão geral · Riscos · Alvos · Varreduras · Painel · Plano | CVSS, confiança, corrigir primeiro; endpoints; ambiente, ferramentas e tipos de teste; no painel: payload/saída bruta e log |
| Dev | Visão geral · **Correções** · Alvos · Varreduras · Painel · Plano | **como corrigir os que mais se repetem** (correção do guia + Cheat Sheet da OWASP), **achados por ambiente** (o que já chegou à produção), corrigir primeiro, status da correção; endpoints e evolução por site; varreduras por dia e duração |
| Estudante | Visão geral · **Aprender** · **Seu progresso** · Painel · Plano | Aprender: cada falha encontrada explicada (o que é, por que é perigosa, onde estudar), **o que é cada severidade** (faixas CVSS da FIRST) e as categorias OWASP explicadas. Progresso: evolução das correções, o que já corrigiu, **próximo passo** (a falha aberta mais frequente, com link), status da correção e prática (varreduras por dia) |
| Admin | todas | tudo |

- **Sem repetição:** os painéis de QA e Pentester deixaram de repetir gráficos que já estão nas abas de relatório.
- **Reconhecimento do tipo de falha** (`role-guides.ts`) ampliado com os títulos reais do Nuclei e do ZAP:
  - `.env`, `git config`, `directory browsing` e `source code disclosure` passam a ser "arquivo exposto";
  - `known vulnerabilities` passa a ser "componente vulnerável";
  - `error disclosure`, `private ip` e `banner` passam a ser "exposição de informação".

### 4.3 Quarta rodada: card com vários relatórios e só achados em aberto
- **Card que troca de relatório** (`shared/components/report-carousel`): um card só, com seta de cada lado e bolinhas embaixo indicando qual relatório está aberto. Também troca pelas setas do teclado. Na visão geral, três cards:
  - **risco:** severidade, status da correção e confiança;
  - **tendência:** achados e varreduras dos últimos 30 dias;
  - **detalhe:** OWASP, tipos mais frequentes (top 10), endpoints e ferramentas.
- **"Tipos mais frequentes" não corta mais os nomes:** as barras deitadas crescem com o número de linhas (30 px por linha). O rótulo do eixo é abreviado em 34 caracteres e o nome completo aparece ao passar o mouse.
- **Dev, "Sugestões de correção":** a lista mostra só os achados **em aberto** (sem os corrigidos e sem os falsos positivos). O número "Críticas e altas" da visão geral também conta só os em aberto.

## 5. Como foi validado
- `ng build` sem erros nem avisos.
- **Funções dos gráficos rodadas com as 26 varreduras reais do banco local** (empacotadas com esbuild):
  - **Por status:** 21 concluídas e 5 canceladas.
  - **Por ambiente:** 26 em DEV.
  - **Por dia:** a soma dos 30 dias é 26.
  - **Duração média:** completa 2,6 min, SQLi 1,5 min e básica 0,1 min.
  - **Evolução por site:** três séries, uma por tipo de teste.
  - **Evolução das correções:** a varredura mais recente mostra os 8 corrigidos e os 5 descartados marcados nela; as anteriores, 0.
  - **CVSS e confiança:** conferidos com 5 achados de nota e confiança conhecidas.
- A validação pegou e corrigiu o erro da comparação entre testes diferentes (ver 4.1).
- **Abas por perfil:** nenhuma aba fica vazia em nenhum perfil. Blocos por aba (Riscos · Varreduras · Alvos):
  - QA: 4 · 4 · 3;
  - Pentester: 3 · 3 · 2;
  - Dev: 4 · 2 · 4.
- **Tipo de falha com os 67 títulos reais** das 5 últimas varreduras:
  - antes: 17 tipos reconhecidos e 29 títulos sem guia, entre eles `.env`, `.git` e código-fonte expostos;
  - depois: 18 tipos e 19 sem guia, quase todos informativos (detecção de tecnologia, cache, WAF);
  - ficaram sem guia 4 falhas reais menos comuns (login padrão do Tomcat, CRLF, XSLT, autenticação fraca), que aparecem pelo título com a explicação da categoria OWASP.
- Não foram escritos testes automatizados (preferência do projeto); `role-panels.spec.ts` só usa funções que continuam exportadas.
- **Pendente:** conferir as abas no navegador com contas QA e Pentester.

## 6. Limitações e riscos conhecidos
- "Evolução por URL" só aparece com a mesma URL varrida mais de uma vez (no Free, só a última varredura é visível).
- Os gráficos de achados do Pentester usam as 5 varreduras concluídas mais recentes (como os painéis já faziam); os de status e ferramenta usam todas.

## 7. Para os slides
- Painel em abas: visão geral, painel do perfil e plano, cada um numa tela.
- QA acompanha o que foi corrigido e o que voltou; Pentester vê onde está o risco (CVSS), o que confirmar e por onde atacar.
- Tudo com os dados que o Checkop já coleta, sem endpoint novo.
