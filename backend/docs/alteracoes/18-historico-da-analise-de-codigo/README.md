# 18 — Histórico da análise de código (só o resumo) e aba exclusiva no Painel

**Data:** 2026-11-27 · **Status:** Implementado (compila; conferido com dados de exemplo) · **Requisitos:** RF-11 (painel por perfil), LGPD art. 6º, III (necessidade) e art. 18

## 1. Problema
A análise de código não guardava nada. Cada análise sumia ao sair da tela. Por isso o Dev e o Estudante não tinham como:
- comparar uma análise com a anterior;
- ver se estavam corrigindo as falhas;
- tirar relatórios.

## 2. Proposta
- Guardar **só o resumo** de cada análise no servidor, **nunca o código**.
- Criar uma aba **"Análise de código"** no Painel para Dev, Estudante e Admin, com comparações, evolução e relatórios.
- Atualizar a Política de Privacidade e os Termos, dizendo exatamente o que é guardado e nada além disso.

**Fora do escopo:** guardar o código, os trechos vulneráveis ou as correções (a escolha do usuário foi o resumo apenas).

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Onde guardar | (1) servidor, só resumo · (2) só no navegador · (3) servidor com o código | **(1)**, escolhida pelo usuário: funciona em qualquer navegador e não guarda código |
| O que entra no resumo | tudo do achado · só o mínimo para comparar | por achado: **título, severidade, categoria, arquivo, linha, regra, ferramentas**; por arquivo: **nome, linguagem, nº de linhas**. Fora: descrição, trecho (`rawResponse`), correções |
| Como saber que é "a mesma falha" em duas análises | título + linha · regra + arquivo | **regra (ou título) + arquivo**: a linha muda quando o código muda; a comparação conta repetições |
| Se gravar o histórico falhar | erro na análise · seguir sem gravar | **seguir**: a análise vale para quem pediu, e o erro fica só no log |
| Controle do usuário | só excluir a conta · apagar pela tela | **apagar uma análise ou o histórico inteiro** na própria aba; entra também no "Baixar meus dados" |

## 4. O que foi implementado
**Backend**
- `prisma/schema.prisma` e a migração `20261128000000_historico_analise_codigo`: modelo `CodeAnalysis`. Ele é apagado junto com a conta (`onDelete: Cascade`).
- `src/lib/code_analysis_history.js`: `summarizeAnalysis()` monta a linha só com os campos permitidos (corta textos longos) e `toHistoryItem()` devolve o JSON aberto.
- `src/controllers/sast_controllers.js`: `analyzeCode` grava o resumo e devolve `historyId`. Novos endpoints (Premium):
  - `GET /api/sast/history` (as 100 mais recentes);
  - `DELETE /api/sast/history/:id` (apaga uma análise);
  - `DELETE /api/sast/history` (apaga o histórico inteiro).
- `src/controllers/auth_controllers.js`: "Baixar meus dados" inclui `codeAnalyses`.
- `src/lib/privacity.js` (versão 2.3): itens 2.4 (o que é e o que não é guardado), 6 (retenção) e 9 (exportação).
- `src/lib/terms_of_use.js` (versão 2.2): itens 7.2 e 7.5. A versão nova pede o novo aceite (alteração 10).

**Front-end**
- `core/services/sast.service.ts`: tipos `SastHistoryItem` e `SastHistoryFinding`, e as chamadas do histórico.
- `pages/Dashboard-page/code-report.ts` (novo): aba "Análise de código", com:
  - **indicadores:** número de análises, achados na última e a diferença para a anterior, críticas e altas, total de corrigidos;
  - **card de evolução**, com quatro relatórios: severidade por análise, corrigidos × novos, categoria por análise e tempo de análise;
  - **card de composição**, com quatro relatórios: categorias da última análise, falhas mais frequentes, achados por linguagem e ferramentas;
  - **comparação de duas análises à escolha:** novos, corrigidos e que continuam; diferença por severidade e por arquivo; listas; CSV da comparação;
  - **listas:** arquivos com mais achados e falhas que se repetem entre análises;
  - **histórico:** tabela com o botão de apagar cada análise, "Apagar histórico" e o relatório em CSV (protegido contra fórmula no Excel);
  - **dica de estudo** para o Estudante.
- `Dashboard-page.component.ts`: aba `code` para DEV, STUDENT e ADM. O link `/dashboard?aba=code` abre direto nela.
- `code-analysis-page`: depois de analisar, mostra "Resumo salvo no histórico (sem o código)" e os atalhos "Perguntar à IA" e "Comparar no painel".
- `account-page`: o texto do "Baixar meus dados" cita o resumo das análises.

## 5. Como foi validado
- `npx prisma migrate deploy`: migração aplicada no banco local.
- `ng build`: sem erros e sem avisos novos (sobra o aviso antigo de tamanho do SCSS do detalhe da varredura).
- **Script de conferência** (sem testes automatizados, conforme a preferência do projeto), com uma análise de exemplo:
  - o resumo gravado **não contém** o trecho vulnerável nem o conteúdo dos arquivos;
  - as contagens por severidade e por categoria batem;
  - as linguagens foram reconhecidas pela extensão;
  - outro usuário não consegue ler a análise.
- **Pendente:** conferir a aba no navegador com várias análises reais.

## 6. Limitações e riscos conhecidos
- O nome do arquivo é guardado. Se o próprio nome tiver informação sensível, ela fica no resumo (está dito na Política).
- Renomear um arquivo entre análises faz as falhas dele aparecerem como "corrigidas" e "novas" na comparação.
- O painel mostra as 100 análises mais recentes. As mais antigas continuam na conta até o usuário apagar.

## 7. Para os slides
- Histórico da análise de código sem guardar código: só nomes, contagens e onde cada falha está.
- Comparação entre duas análises: o que é novo, o que foi corrigido e o que continua, por severidade e por arquivo.
- Aba exclusiva para Dev e Estudante, com evolução, falhas que se repetem e relatórios em CSV.
- Privacidade: a Política e os Termos listam exatamente os campos guardados, e o usuário apaga tudo quando quiser.
