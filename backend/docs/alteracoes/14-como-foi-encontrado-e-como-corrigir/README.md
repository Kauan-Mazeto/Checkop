# 14 — "Como foi encontrado" e "Como corrigir" para qualquer achado

**Data:** 2026-11-26 · **Status:** Implementado (compila; falta varrer de novo para ver os campos novos) · **Requisitos:** RF-20, RF-21

## 1. Problema
Num SQLi do laboratório (`/item?id='`), a tela mostrava só `HTTP/1.1 500 Internal Server Error` como prova:

- **Sem amostra:** não aparecia a requisição nem o corpo com o erro do MySQL. O motor buscava a mensagem HTTP só dos **300 primeiros alertas** do ZAP, na ordem em que vinham. Numa varredura completa, o achado crítico ficou de fora.
- **Sem "como":** o ZAP explica em `otherinfo` como concluiu e manda links em `reference`, mas o motor descartava os dois. O achado tinha **confiança baixa** (o ZAP só viu um 500) e a tela mostrava CRÍTICO 9,8 sem nenhum aviso.
- **"Como corrigir" ruim:** colava o texto genérico e longo da regra (JDBC, ASP, stored procedures...). O Nuclei punha "Referências: url, url" dentro do texto. Sem correção, a aba aparecia mesmo assim, só para dizer que não havia nada.

## 2. Proposta
Valer para **qualquer achado de qualquer ferramenta**, não só para o SQLi:

1. Buscar primeiro a amostra dos achados mais graves.
2. Guardar como a ferramenta concluiu (`detection`) e os links dela (`references`).
3. Mostrar o passo a passo da detecção e o que a confiança significa.
4. Resumir a correção, com referências, e esconder a aba quando não houver conteúdo.

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Ordem da amostra | Aumentar o limite; priorizar | Priorizar: primeiro um alerta de cada regra (o mais grave), do mais grave para o mais leve. O limite de 300 protege o tempo da varredura. |
| Resumo da correção | Cortar o texto da ferramenta; texto próprio | Texto próprio, revisado à mão, para as 19 classes dos guias (SQLi, XSS, CSRF...). Para as outras, os 3 primeiros itens do texto da ferramenta. O texto completo fica recolhido. |
| Referências | Só da ferramenta; só OWASP | As duas: Cheat Sheet da OWASP da classe, links da ferramenta, categoria OWASP Top 10 e CWE, sem repetir, até 5. |
| Quando esconder a aba | Sem texto; sem texto e sem guia | Esconde quando não há resumo, guia da classe nem link da ferramenta. Links genéricos (só OWASP/CWE) não bastam. |
| Planos e perfis | — | `detection` é Premium (faz parte da prova), sai no Modo Seguro e no perfil Estudante (cita o payload). `references` é livre. |

## 4. O que foi implementado
- **Motor**
  - `zap_runner.py`:
    - `_poc_priority` ordena a busca das mensagens.
    - `detection` vem de `other` e `references` vem de `reference` (até 5 URLs).
    - Sem a mensagem HTTP, a evidência é gravada já marcada.
  - `nuclei_runner.py`: `detection` diz qual template e qual matcher bateram e o valor capturado. Os links vão para `references` e saem da correção.
  - `schemas.py`: os dois campos novos.
- **Backend**
  - `prisma/schema.prisma` e a migração `20261127000000_deteccao_e_referencias`: colunas `detection` e `references`.
  - `finding_translation.js`: `detection` é traduzido como os outros textos.
  - `finding_serializer.js`: os cortes de plano, Modo Seguro e perfil da tabela acima.
  - `finding_groups.js`: `detection` por ocorrência.
- **Front** (`scan-detail-page`)
  - **Como corrigir:** "O que fazer" (curto), "Referências e exemplos" e "Ver o texto completo da ferramenta". A aba some quando não há conteúdo.
  - **Evidência:** abre com "Como foi encontrado": ataque e parâmetro, o sinal na resposta, a conclusão da ferramenta e o que a confiança quer dizer.
  - **Topo do achado:** selo "Confiança baixa".
  - **Guias** (`role-guides.ts`): campo `fix` nas 19 classes, mais `summarizeRemediation`, `toolReferenceLinks` e `fixReferenceLinks`.

## 5. Como foi validado
- Migração aplicada no banco local (`prisma migrate deploy`) e cliente regenerado.
- Python compilado (`py_compile`); front compilado (`ng build`) sem erros nem avisos.
- Não foram escritos nem rodados testes (preferência do projeto).
- **Pendente:**
  - Reiniciar o motor e o backend.
  - Varrer o laboratório de novo: os achados antigos não têm `detection` nem `references`.
  - Conferir na tela o SQLi e um achado do Nuclei.

## 6. Limitações e riscos conhecidos
- A severidade continua vindo da regra: um SQLi de confiança baixa segue CRÍTICO, agora com o aviso. Rebaixar a severidade pela confiança mudaria a nota CVSS; fica para decidir.
- O resumo automático (classes sem guia) depende de como a ferramenta escreveu o texto.

## 7. Para os slides
- Cada achado diz **como** foi encontrado: o ataque enviado, o sinal na resposta e a conclusão da ferramenta.
- A confiança aparece em linguagem simples. Um "500 depois da aspa" não é tratado como prova.
- A correção vem em poucos itens, com links da OWASP e da própria ferramenta, para qualquer tipo de falha.
