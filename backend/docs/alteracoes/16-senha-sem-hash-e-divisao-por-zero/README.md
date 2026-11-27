# 16 — Senha gravada sem hash e divisão por zero

**Data:** 2026-11-26 · **Status:** Implementado e conferido com exemplos reais · **Requisitos:** espec.txt 3.2 (análise de código)

## 1. Problema
Num controller Spring com 6 problemas, a análise achou 4. Escaparam:
- **a senha gravada como veio** no `INSERT` (`usuario.getSenha()` direto para o banco). A regra existente só pegava a senha **comparada** no SQL (`WHERE senha = ...`);
- **a divisão por um número da URL** (`/dividir/{a}/{b}` → `a / b`), que com `b = 0` derruba a requisição com erro 500.

## 2. Proposta
Duas regras, valendo para os frameworks principais e não só para o exemplo:
- **Senha sem hash:** por SQL (`INSERT ... VALUES` / `UPDATE ... SET`) em qualquer linguagem, e pelo ORM em cada uma.
- **Divisão por zero:** divisor vindo da requisição, sem checagem antes.

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Senha por SQL | Uma regra por linguagem; uma por texto | Uma regra por texto (regex) para 9 linguagens. O SQL é texto igual em todas. Fica de fora quando há chamada de hash no mesmo comando (`encode`, `hash`, `bcrypt`, `argon2`...). |
| Senha pelo ORM | Só SQL; cada ORM | Cada um, pelo jeito de cada framework: `setSenha(...)` (JPA), `{ senha: ... }` em `create/save/update` (Prisma, TypeORM, Sequelize, Mongoose), `Model(senha=...)`/`obj.password = ...` (Django, SQLAlchemy), `'password' => ...` (Laravel), `Senha = ...` (EF Core). |
| Senha que já vira hash | — | Fica de fora: valor com hash/encode/crypt no nome (inclusive numa variável `senhaHash` feita antes), `create_user`/`set_password` do Django e `authenticate`/`login`. |
| Divisor | Qualquer divisão; só valor da requisição | Só divisor vindo da requisição: `@PathVariable`/`@RequestParam` (Spring), parâmetro da rota (Flask, FastAPI), `req.params/query/body` (Express), `$request->...` (Laravel), parâmetro de action (ASP.NET). Divisão por constante ou por valor já checado não entra. |
| Categoria da divisão | Segurança; lógica | Lógica (CWE-369): derruba a requisição, não expõe dado. |
| Nome da regra de SQL | — | O id não pode ter "sql": o `sast_runner` classifica pelo nome e juntava a regra com o SQL Injection, sumindo com ela. |

## 4. O que foi implementado
`backend/src/py/security_engine/app/rules/checkop/senha-e-divisao.yaml` (novo):
- **Senha gravada sem hash:**
  - `checkop-senha-gravada-sem-hash-insert` (SQL, 9 linguagens);
  - `-java`, `-js`, `-python`, `-php` e `-csharp` (ORM de cada linguagem).
- **Divisão por zero:** `checkop-divisao-por-valor-da-requisicao-java`, `-python`, `-js`, `-php` e `-csharp`.

## 5. Como foi validado
- **Exemplos:** vulnerável e corrigido para Java/Spring, Python (FastAPI+Flask), TS (NestJS/Prisma+Express), PHP/Laravel e C#/ASP.NET Core.
- **Regras sozinhas:** 17 falhas achadas nos vulneráveis; **0** nos corrigidos.
- **Pipeline do motor**, com o controller do problema:

  | | Antes | Agora |
  |---|---|---|
  | Falhas achadas | 4 de 6 | 6 de 6 |

  Os cards de agora:
  - SQLi + dados sensíveis na resposta;
  - senha sem hash + SQLi do cadastro;
  - divisão por zero;
  - erro de compilação.

  Versão corrigida: 0 cards.
- Não foram escritos testes automatizados (preferência do projeto).

## 6. Limitações e riscos conhecidos
- A senha é reconhecida pelo nome (`senha`, `password`, `passwd`, `pwd`). Um campo com outro nome não é pego.
- Divisão no Django por `request.GET[...]` e no NestJS por `@Param()` ainda não é coberta.
- No JS, a divisão por zero não quebra: dá `Infinity`/`NaN`, e o texto da regra explica isso.

## 7. Para os slides
- A análise pega a senha guardada em texto puro em qualquer framework: por SQL ou pelo ORM.
- Também pega o "500 por divisão por zero" quando o número vem da URL.
- Cada regra nova foi conferida em código vulnerável e corrigido de 5 linguagens: acha a falha e fica quieta no código certo.
