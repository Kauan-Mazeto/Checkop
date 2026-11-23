# 09 — Alertas antigos do ZAP e uma varredura por usuário

**Data:** 2026-11-22 · **Status:** Implementado e testado · **Requisitos:** RF-33 (varredura web), comparação entre varreduras

## 1. Problema
Itens 1.1 e 1.2 da lista de pendências (documento 08).

**Alertas antigos voltando.** O motor lia o resultado com `core/view/alerts?baseurl=<alvo>`, que devolve **todos os alertas da sessão do ZAP para aquele alvo**, e nada era apagado entre varreduras. Uma falha corrigida voltava na varredura seguinte, e a aba Comparação a mostrava como "persistente".

Reproduzido com o ZAP 2.17 do Docker: site sem cabeçalhos de segurança → 4 tipos de alerta. Depois de "corrigido" (passou a mandar CSP, X-Frame-Options e X-Content-Type-Options) e varrido de novo → **os 4 alertas continuaram**.

**Varreduras simultâneas.** Nada impedia o mesmo usuário de disparar várias varreduras ao mesmo tempo.

**Reinício do backend.** Já estava tratado: ao subir, o backend marca como `FAILED` as varreduras presas em `RUNNING`. Faltava avisar o motor, que é outro processo e continuava varrendo para ninguém.

## 2. Proposta
- Antes de cada varredura, apagar os alertas antigos **só do alvo** dela.
- **Uma varredura em execução por usuário.** Usuários diferentes rodam ao mesmo tempo.
- Ao subir, o backend pede ao motor que cancele as varreduras órfãs.

Fora do escopo: vários ZAPs (um por varredura), limite diferente por plano e fila durável. Ficam para a fase SaaS (ver seção 6).

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Como limpar os alertas | `newSession`; `deleteAllAlerts`; `alert/action/deleteAlerts` por alvo | **`deleteAlerts?baseurl=<alvo>`**: apaga só o alvo desta varredura. `newSession` e `deleteAllAlerts` apagariam também a varredura em andamento de outro usuário. No ZAP 2.17 essa ação apaga em lotes (78 → 32 → 12 → 0 no teste real), então o motor repete até zerar (no máximo 10 vezes). Se não conseguir, a varredura segue com um aviso. |
| Limite de varreduras simultâneas | Fila global do ZAP; limite por usuário | **Por usuário (1 por vez)**. Uma fila global deixaria um usuário só usando o ZAP no servidor inteiro, o que não faz sentido para o produto. |
| Onde aplicar o limite | Contar antes e depois reservar; condição no próprio UPDATE | **No mesmo UPDATE que reserva a varredura** (`user: { scans: { none: { status: 'RUNNING' } } }`): dois cliques simultâneos em varreduras diferentes não passam juntos. |

## 4. O que foi implementado
- [zap_runner.py](../../../src/py/security_engine/app/zap_runner.py): `_clear_target_alerts`, chamada no início de `run_zap_scan`, antes do primeiro acesso ao alvo.
- [scan_controllers.js](../../../src/controllers/scan_controllers.js): `runScan` só reserva se o usuário não tiver outra varredura `RUNNING`. Caso tenha, responde 409 "Você já tem uma varredura em execução. Aguarde ela terminar (ou cancele) para iniciar outra." O front já mostra a mensagem que vem da API.
- [server.js](../../../src/server.js): ao subir, chama `cancelEngineJob` para cada varredura `RUNNING` antes de marcá-la `FAILED`.
- Testes: [test_zap_session.py](../../../src/py/security_engine/tests/test_zap_session.py) (novo) e 3 casos novos em [scan_run_guard.test.js](../../../src/tests/scan_run_guard.test.js).

## 5. Como foi validado
**Testes automatizados**
- `npm run test:engine`: 78 testes OK. São 5 novos: apaga antes de acessar o site, repetindo até zerar; apaga só o alvo, sem `newSession` nem `deleteAllAlerts`; sem alertas antigos não apaga nada; falha na limpeza vira aviso; limpeza que nunca zera desiste com aviso.
- `npm test`: 160 testes OK. São 3 novos: a reserva leva a condição por usuário; com outra varredura rodando → 409 com a mensagem do limite; a mesma varredura já rodando mantém a mensagem de duplo clique.

**Banco real (SQLite temporário, mesma consulta do controller)**

| Cenário | Resultado |
|---|---|
| Usuário U dispara 2 varreduras e o usuário V dispara 1, as três no mesmo instante | U: 1 reservada, 1 recusada · V: reservada |
| U tenta outra enquanto a dele roda | recusada |
| U tenta de novo depois que a dele termina | reservada |

**Com o ZAP real (Docker, zap-stable 2.17.0), varredura passiva**

| Cenário | Antes | Depois |
|---|---|---|
| Site varrido, corrigido e varrido de novo | os 4 alertas antigos continuaram | os 3 alertas corrigidos sumiram; ficou só "Server Leaks Version", que é real (o servidor de teste sempre envia `Server`) |
| Site corrigido e laboratório varridos ao mesmo tempo | — | rodaram em paralelo (2 s cada); cada resultado só tem achados do próprio host |

Os scripts estão nesta pasta: [repro_zap_session.py](repro_zap_session.py) (o "antes") e [validate_zap_alertas.py](validate_zap_alertas.py) (o "depois"). Eles sobem um servidor descartável na porta 3999 dentro do container do motor. Para rodar: `docker compose exec -T engine python - < <script>`.

## 6. Limitações e riscos conhecidos
- **Um só ZAP para todos os usuários.** As configurações do ZAP valem para a instância inteira: regras ativas, velocidade, opções do AJAX Spider e usuário autenticado ("forced user"). Quando dois usuários varrem ao mesmo tempo, a última varredura a configurar vale para as duas. Exemplo: uma de SQLi enquanto outra completa roda; ou uma em produção (lenta, RF-51) junto com uma local (rápida).
- **Dois usuários no mesmo alvo ao mesmo tempo** (ex.: `http://localhost:3000`): um apaga ou recebe os alertas do outro, porque o alvo é o mesmo.
- Os dois casos acima só se resolvem com **um ZAP por varredura**. É a arquitetura de SaaS: fila durável (Redis/Postgres) e workers com o motor e um ZAP próprio cada um, que se multiplicam conforme a demanda.

## 7. Para os slides
- Falha corrigida voltava como "persistente": o ZAP acumulava alertas entre varreduras. Agora cada varredura apaga os alertas antigos do alvo antes de começar.
- Validado com o ZAP real: antes 4 alertas antigos voltavam, depois 0.
- Uma varredura em execução por usuário, garantida no banco (à prova de clique duplo); usuários diferentes varrem em paralelo.
- Próximo passo para SaaS: um ZAP por varredura (workers que escalam com a demanda).
