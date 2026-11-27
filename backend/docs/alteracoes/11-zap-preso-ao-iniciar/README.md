# 11 — ZAP que não subia no iniciar.cmd

**Data:** 2026-11-26 · **Status:** Implementado e testado · **Requisitos:** —

## 1. Problema
Ao rodar `iniciar.cmd`, às vezes o script terminava com:

```
[!]  ZAP não respondeu em 3 min: veja a janela 'ZAP' para o erro.
```

Rodado sozinho, o ZAP subia normalmente em 10 a 20 s. O log do ZAP (`%USERPROFILE%\ZAP\zap.log`) não tinha nenhuma linha da tentativa que falhou, ou seja, o ZAP morria antes de começar a carregar.

A causa mais provável é a trava da pasta do ZAP. Só um ZAP pode usar `%USERPROFILE%\ZAP` por vez. O `parar-tudo.ps1` só encerrava processos **que estavam escutando nas portas**. Um ZAP que ainda estava subindo, ou que travou antes de abrir a 8091, continuava vivo e segurando a pasta. O mesmo vale para o ZAP com janela, quando aberto à mão. Com isso, o próximo ZAP aberto pelo `iniciar` fechava na hora.

Além disso, quando o ZAP falhava, o aviso só mandava olhar a janela dele, que podia já ter fechado.

## 2. Proposta
- Antes de abrir o ZAP, fechar qualquer ZAP que tenha sobrado sem a porta 8091 aberta.
- No `parar-tudo`, encerrar também o ZAP pelo processo (jar), e não só pela porta.
- Gravar a saída do ZAP num arquivo e, se ele não subir, mostrar as últimas linhas no próprio terminal do `iniciar`.

Fora do escopo: a subida via Docker (`docker-compose.yml`), que roda o ZAP isolado no container e não tem esse problema.

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Como achar o ZAP preso | Pela porta; pelo nome do processo; pela linha de comando | Pela linha de comando (`zap-<versão>.jar`) e pelo `ZAP.exe`. Um ZAP preso não tem porta aberta, e "java" sozinho pegaria outros programas Java. |
| Fechar ou só avisar | Avisar e parar o script; fechar sozinho | Fechar e avisar com `[fechando]`: com outro ZAP vivo, o novo nunca sobe, então avisar sem fechar só adia o problema. |
| Onde guardar a saída | Pasta do projeto; `%TEMP%` | `%TEMP%\checkop-zap.log`: é um arquivo temporário de diagnóstico e não deve ir para o git nem para o OneDrive. |

## 4. O que foi implementado
- `scripts/iniciar-tudo.ps1`
  - Antes de abrir o ZAP, se a 8091 está livre, encerra qualquer `java`/`javaw` rodando `zap-*.jar` e qualquer `ZAP.exe`.
  - A janela do ZAP agora grava a saída em `%TEMP%\checkop-zap.log` (com `Tee-Object`), sem deixar de mostrar a saída na janela.
  - Se o ZAP não responder em 3 min, o terminal mostra as últimas 15 linhas desse arquivo.
- `scripts/parar-tudo.ps1`
  - Além de encerrar pelas portas, encerra todo `java` rodando `zap-*.jar`.

## 5. Como foi validado
- Sintaxe dos dois scripts verificada com o parser do PowerShell: sem erros.
- ZAP aberto com o mesmo comando da janela do `iniciar`: subiu em ~11 s, e a saída foi gravada em `%TEMP%\checkop-zap.log`.
- O filtro de limpeza achou o processo do ZAP (1 processo) e o encerrou. Depois disso, a porta 8091 ficou livre e não sobrou nenhum `java` com o ZAP.
- Ainda não testado: a falha original do `iniciar.cmd`. Ela não se repetiu durante o teste, por isso a causa da seção 1 é a mais provável, mas não foi confirmada.

## 6. Limitações e riscos conhecidos
- Se alguém abrir o ZAP com janela de propósito enquanto o Checkop não está rodando, o `iniciar` fecha esse ZAP. É o comportamento desejado, porque os dois não conseguem rodar juntos.
- Se o ZAP falhar por outro motivo (ex.: falta de Java), o script não corrige, mas agora mostra o erro na tela.

## 7. Para os slides
- O ambiente local sobe com um clique (`iniciar.cmd`): ZAP, motor, backend, front e laboratório.
- Um ZAP preso de uma execução anterior travava a subida, e agora é fechado sozinho.
- Quando algo falha, o erro aparece direto no terminal, sem precisar caçar janelas.
