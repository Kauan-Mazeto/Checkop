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

## Como rodar os testes

```bash
cd backend
npm test             # API Node (node:test)
npm run test:engine  # motor Python (unittest)

cd ../front-end
npm run test:ci      # Angular (Karma); sem Chrome, defina CHROME_BIN para o msedge.exe
```
