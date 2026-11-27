# Registro de alterações do Checkop

Cada pasta aqui documenta **uma alteração** do projeto: o problema encontrado, a proposta, as decisões tomadas, o que foi implementado e como foi validado. Serve de memória do projeto e de fonte para os slides da apresentação do TCC; cada documento termina com uma seção **"Para os slides"**.

## Convenção

- Uma pasta por alteração: `NN-nome-curto/` (NN = ordem cronológica).
- Dentro dela, um `README.md` seguindo o [modelo](_modelo/README.md).
- Arquivos extras (diagramas, prints, saídas de teste) ficam na mesma pasta.
- Requisitos citados usam os códigos de [Requisitos_Funcionalidades_Backend.md](../Requisitos_Funcionalidades_Backend.md) (RF-xx / RNF-xx).

## Índice

| # | Alteração | Status | Data |
|---|---|---|---|
| 01 | [Levantamento de pendências do backend](01-levantamento-de-pendencias/README.md) | Concluído (análise) | 2026-11-09 |
| 02 | [Correções de segurança B1–B10](02-correcoes-de-seguranca/README.md) | Implementado e testado | 2026-11-09 |
| 03 | [Verificação de propriedade do alvo e opt-in de varredura ativa](03-verificacao-de-dominio/README.md) | Implementado e testado | 2026-11-09 |
| 04 | [Objetivos de varredura da matriz e filtro por objetivo](04-objetivos-de-varredura/README.md) | Implementado e testado | 2026-11-09 |
| 05 | [Front-end: fluxo real de varredura, resultados e gráficos](05-front-end-fluxo-de-varredura/README.md) | Implementado e testado | 2026-11-09 |
| 06 | [Visual da equipe nas telas logadas e regras Free/Premium](06-visual-da-equipe-e-planos/README.md) | Implementado e testado | 2026-11-16 |
| 07 | [Login com Google](07-login-com-google/README.md) | Implementado e testado | 2026-11-16 |
| 08 | [Análise de código: novas ferramentas e medição de acerto](08-analise-de-codigo-novas-ferramentas/README.md) | Implementado (ferramentas); medição pendente | 2026-11-23 |
| 09 | [Alertas antigos do ZAP e uma varredura por usuário](09-alertas-do-zap-e-limite-por-usuario/README.md) | Implementado e testado | 2026-11-22 |
| 10 | [Novo aceite dos Termos e "Baixar meus dados"](10-novo-aceite-dos-termos-e-baixar-meus-dados/README.md) | Implementado e testado | 2026-11-22 |
| 11 | [ZAP que não subia no iniciar.cmd](11-zap-preso-ao-iniciar/README.md) | Implementado e testado | 2026-11-26 |
| 12 | [Laboratório com um exemplo de cada falha](12-laboratorio-com-todas-as-falhas/README.md) | Implementado; validação com Nuclei/ZAP pendente | 2026-11-26 |
| 13 | [Novo visual da landing, do login e do cadastro](13-landing-login-e-cadastro/README.md) | Implementado (compila) | 2026-11-26 |
| 14 | ["Como foi encontrado" e "Como corrigir" para qualquer achado](14-como-foi-encontrado-e-como-corrigir/README.md) | Implementado (compila) | 2026-11-26 |
| 15 | [Análise de código: frameworks principais, sem duplicatas](15-analise-de-codigo-frameworks-e-duplicatas/README.md) | Implementado e conferido com exemplos | 2026-11-26 |
| 16 | [Senha gravada sem hash e divisão por zero](16-senha-sem-hash-e-divisao-por-zero/README.md) | Implementado e conferido com exemplos | 2026-11-26 |
| 17 | [Painel em abas, relatórios e gráficos por perfil](17-painel-em-abas-e-graficos-por-perfil/README.md) | Implementado e conferido com dados reais | 2026-11-26 |
| 18 | [Histórico da análise de código (só o resumo) e aba no Painel](18-historico-da-analise-de-codigo/README.md) | Implementado (compila; conferido com exemplo) | 2026-11-27 |
| 19 | [Ajuda por IA](19-ajuda-por-ia/README.md) | Implementado (compila); chamada real à IA pendente | 2026-11-27 |

## Como rodar os testes

```bash
cd backend
npm test             # API Node (node:test)
npm run test:engine  # motor Python (unittest)

cd ../front-end
npm run test:ci      # Angular (Karma); sem Chrome, defina CHROME_BIN para o msedge.exe
```
