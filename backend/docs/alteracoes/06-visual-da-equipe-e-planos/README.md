# 06 — Visual da equipe nas telas logadas e regras Free/Premium

**Data:** 2026-11-16 · **Status:** Implementado e testado · **Requisitos:** RF-11, RF-12, RF-13, RNF-03, espec.txt seções 2 e 3

## 1. Problema
- Duas versões do front-end foram feitas em paralelo. A branch `front` (Kauan, 05/11) tinha o visual definido pela equipe: cinzas neutros, fonte do sistema, sem brilhos nem animações ("menos cara de IA"), além de um painel com um bloco por perfil. A `master` (alteração [05](../05-front-end-fluxo-de-varredura/README.md)) tinha o fluxo completo de varredura, mas outro visual. O visual da equipe nunca chegou à `master`.
- Um `git merge` da `front` traria conflito em quase todo o front e arquivos que não podem voltar ao repositório: `backend/prisma/database.db` (dados pessoais, removido na correção B2) e oito READMEs de outro projeto.
- As regras de plano eram diferentes nas duas versões. Na `front`, o Free tinha 1 varredura por dia, só o scan básico, só o último resultado e nenhuma exportação. Na `master`, o Free podia tudo, menos a correção, a PoC, o compliance e o SAST. Além disso, as regras da `front` existiam só na tela, e o próprio código delas avisava: "quem garante é a API".
- Não existia um objetivo de "scan básico": a `front` usava `KNOWN_CVE` como substituto provisório.

## 2. Proposta
Manter a `master` como base: rotas separadas, fluxo de varredura e testes. Por cima dela, portar à mão o visual e os painéis por perfil da `front`. Juntar as regras de plano das duas versões e aplicá-las também no servidor.

**Fora do escopo:** cobrança real (TCC 6.3), o recurso de equipes da `front` (era só dado de exemplo, sem backend) e a análise de código simulada da `front`, porque a `master` já tem o SAST real.

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Como trazer a `front` | `git merge` · portar à mão | **Portar à mão.** O merge traria o banco com dados pessoais e READMEs alheios, e desfaria rotas e testes da `master`. |
| Estrutura das telas | Página única com rolagem (`front`) · rotas separadas (`master`) | **Rotas separadas**, como a equipe pediu ("separar as páginas melhor"). O painel do perfil e a comparação de planos da `front` entraram no Painel. |
| Regras do Free | Só as da `master` · só as da `front` · as duas | **As duas somadas.** O Free tem 1 varredura por dia, só o scan básico, só a varredura mais recente e nenhum relatório. Também não vê correção, PoC, compliance nem SAST. |
| Onde aplicar | Só na tela · tela e API | **Na API** (`constants/plans.js`). A tela só avisa antes. |
| Scan do Free | `KNOWN_CVE` · objetivo novo | **Objetivo novo `BASIC_SCAN`**, só passivo: cabeçalhos, cookies, clickjacking, vazamento de informação e TLS. É o "relatório sintomático" do espec.txt (seção 2), sem enviar ataque. |
| Limite diário | Últimas 24 h · dia do calendário | **Dia do calendário** (zera à meia-noite do servidor), como na `front`. |
| Gráficos | Barras CSS da `front` · Chart.js | **Os dois.** O Chart.js fica nos gráficos do Painel (previsto na proposta, TCC 7.1) e as barras CSS no painel de QA. |

## 4. O que foi implementado
**Backend**
- `src/constants/plans.js` (novo) concentra as regras de cada plano: limite diário, objetivos permitidos, objetivo padrão e quantas varreduras ficam visíveis. Plano desconhecido cai no Free.
- `scan_controllers.js`:
  - `POST /api/scans`: sem objetivo, usa o padrão do plano. Objetivo bloqueado devolve 403 `PREMIUM_REQUIRED`. Passar do limite do dia devolve 429 `DAILY_SCAN_LIMIT`.
  - `GET /api/scans` e `/stats`: no Free, consideram só a varredura mais recente.
  - `GET /api/scans/:id`: no Free, uma varredura antiga devolve 403 `PREMIUM_REQUIRED`.
  - `POST /api/scans/:id/run`: uma varredura de objetivo Premium não roda depois que a conta volta ao Free.
- `scan_objectives.js` e `schema.prisma`: objetivo `BASIC_SCAN`. Não precisa de migração, porque no SQLite o enum é texto. Mesmo assim é preciso rodar `npm run prisma:generate`.
- `scan_validator.js`: `objective` passou a ser opcional, porque quem decide o padrão é o plano.

**Front-end**
- **Visual:** o patch de estilo da `front` foi aplicado na landing, no login e no cadastro. Nas telas logadas, os tokens de `src/styles/_app-ui.scss` foram trocados pela paleta da equipe (`#111213`, `#191a1c`, `#303135`, vermelho `#d84a56`). As cores fixas nas páginas e nos gráficos foram convertidas e a tela de Planos perdeu os gradientes.
- **Menu (`app-shell`):** formato da `front`, com texto sem ícones, o item ativo em vermelho e o cartão "Perfil atual" com o perfil e o plano. Ganhou o botão **Alto contraste**, que fica lembrado no navegador. O selo PRO aparece no que o plano não libera.
- **Painel:**
  - cabeçalho, faixa de orientação e 4 indicadores, um deles com as varreduras restantes hoje;
  - 2 gráficos;
  - o painel do perfil (`role-panels.ts`, portado da `front` com dados reais):
    - QA: severidade, tipos, relatórios e URLs repetidas;
    - Dev: alertas e sugestões de correção;
    - Pentester: log, payload e saída bruta, com filtros;
    - Estudante: explicações;
  - a tabela de últimas varreduras e a comparação de planos.
- **Regras na tela** (`shared/ui/plans.ts`, espelho do backend):
  - Nova varredura: no Free, o tipo de teste é fixo e a tela mostra quantas varreduras restam hoje.
  - Histórico: no Free, vira "Último scan".
  - Detalhe: o PDF e o JSON ficam no Premium.
  - Conta e Planos: textos atualizados.

## 5. Como foi validado
- **Backend:** `npm test` passa com **90 testes**. Os 15 novos estão em `plan_scan_rules.test.js` e cobrem:
  - o padrão do plano;
  - objetivo bloqueado, sem gravar nada;
  - o limite diário, contado a partir da meia-noite;
  - o Premium sem limite;
  - a listagem, o detalhe e as estatísticas restritos no Free;
  - a execução bloqueada depois de voltar ao Free.
- O teste de integridade dos objetivos já confere que o `BASIC_SCAN` está no enum do Prisma, que os ids do ZAP são válidos e que ele não envia ataque.
- **Front:** `ng build` (produção) passa. `npm run test:ci` passa com **51 testes**. Os novos cobrem:
  - as regras de plano e a contagem do dia;
  - os painéis por perfil (contagens, tipos, URLs repetidas);
  - o corte entre Free e Premium nos painéis de Dev e Pentester;
  - o scan básico no grupo certo do seletor.
- **Não validado:** clique a clique no navegador e varredura real com o ZAP. Isso fica para o ensaio da demonstração.

## 6. Limitações e riscos conhecidos
- **A exportação PDF/JSON é bloqueada só na tela.** O Free já recebe o diagnóstico pela API, e o relatório é montado no navegador a partir desses mesmos dados. Bloquear de verdade exigiria o servidor gerar o arquivo.
- O limite diário usa o fuso do servidor.
- O Free com uma varredura que falhou pode executá-la de novo. A regra limita a criação de varreduras, não as novas tentativas.
- **Na demonstração**, use a tela de Planos para alternar entre Free e Premium. O Free gasta a varredura do dia no primeiro teste.

## 7. Para os slides
- **Uma tela, duas camadas:** o Free faz um diagnóstico rápido e passivo por dia. O Premium escolhe entre 25 tipos de teste e recebe a prova, a correção, o compliance, o histórico e o relatório.
- **Regra de negócio no servidor:** o plano é conferido na API, com um código de erro claro para cada caso. Esconder na tela não basta.
- **Painel por perfil (RF-11):** QA vê relatórios, Dev vê alertas e correções, Pentester vê payloads e Estudante vê explicações.
- **Visual definido pela equipe:** sóbrio, sem efeitos, com alto contraste para acessibilidade (RNF-03).
