# 15 — Análise de código: frameworks principais, sem duplicatas

**Data:** 2026-11-26 · **Status:** Implementado e conferido com exemplos reais · **Requisitos:** espec.txt 3.2 (análise de código)

## 1. Problema
Um controller Spring com 3 falhas comentadas (SQLi em `/buscar`, login que aceita qualquer senha, `orElseThrow()` sem tratamento) gerou 4 cards:

- **Duplicado:** o SQLi de `/buscar` virou dois cards, um na linha que monta o SQL e outro na que executa. O "variável não usada" do PMD virou um card à parte, na mesma linha do SQLi do login.
- **Incompleto:** não apontou o login que aceita tudo, a resposta com a linha inteira do banco (senha junto) nem o erro não tratado.
- **Só a linguagem pura:** o modo completo só tinha pacotes de framework para Python (Flask, Django). Spring, Laravel, NestJS, Express, Rails, ASP.NET Core e Go ficavam só com as regras da linguagem.

O mesmo teste mostrou que o `tsc` acusava "erro de sintaxe" nos decorators do NestJS (`@Get(...)`) e "nome não definido" em trecho colado sem imports.

## 2. Proposta
- Regras do Checkop para os frameworks que o registro do Semgrep não cobre.
- Os pacotes oficiais de framework que existem, no modo completo.
- Juntar a mesma falha em linhas vizinhas e a boa prática que cai na linha de uma falha.
- O `tsc` aceitando decorators de framework.

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Quais pacotes | Adivinhar nomes; conferir no registro | Conferidos um a um em semgrep.dev: nome inexistente derruba a análise inteira. Existem e entraram `findsecbugs`, `expressjs`, `nodejsscan`, `react`, `fastapi`, `brakeman`, `gosec`, `phpcs-security-audit` e os de tema `sql-injection`, `command-injection`, `xss`, `jwt`. **Não existem** (ou vêm vazios): Spring, Laravel, NestJS, Next.js, ASP.NET. |
| Frameworks sem pacote | Deixar de fora; regras próprias | Regras próprias em `rules/checkop/frameworks.yaml`, que rodam nos dois modos (essencial e completo). |
| SQLi no Spring | Padrão de texto; fluxo (taint) | Taint: segue o valor do `@RequestParam`/`@PathVariable`/`@RequestBody` até o `JdbcTemplate`/`EntityManager`/JDBC, passando por concatenação e variáveis. |
| Login que aceita tudo | Qualquer `return`; só resposta fixa | Só quando o método de login devolve resposta **fixa** (`"Logado"`, `true`, `Ok(...)`, `jsonify(...)`) **sem nenhum `if`** antes. `return authService.login(...)` repassa a decisão e não é apontado. |
| Juntar linhas vizinhas | Só linhas sobrepostas; janela | Janela de 2 linhas **só nas falhas de fluxo** (injeção de SQL, comando, código, XSS, caminho, SSRF, redirect, desserialização). O card mostra o trecho inteiro (ex.: 11-12). |
| Boa prática na linha de uma falha | Card à parte; dentro da falha | Dentro do card da falha ("Também neste trecho"). |
| Nome não definido no TS | Sempre; nunca | Ignorado só em arquivo **sem nenhum import** (trecho colado). Com imports, continua valendo. |

## 4. O que foi implementado
- `rules/checkop/frameworks.yaml` (novo):
  - **Spring:**
    - SQL injection por fluxo (`checkop-spring-sql-injection`);
    - login que aceita qualquer senha;
    - linha do banco devolvida na API (`queryForRowSet`/`queryForList`/`queryForMap`);
    - `orElseThrow()` sem argumento num endpoint.
  - **NestJS/TypeORM/Prisma/Sequelize/Knex:** SQL com `${}` ou `+` (inclui `$queryRawUnsafe`).
  - **Express:** rota de login sem decisão.
  - **Flask/Django/FastAPI:** login sem decisão.
  - **Laravel:** SQL em `DB::select`/`whereRaw`/`orderByRaw`... com interpolação; `Model::create($request->all())` (atribuição em massa).
  - **ASP.NET Core/EF Core:** `FromSqlRaw`/`ExecuteSqlRaw` com interpolação ou `+`; login sem decisão.
- `sast_runner.py`:
  - **Pacotes no modo completo:** os de framework (`SEMGREP_LANGUAGE_PACKS`) e os de tema (`SEMGREP_TOPIC_PACKS`).
  - **Deduplicação:** `_dedupe_results` junta linhas vizinhas nas falhas de fluxo e estende o trecho do card.
  - **Boa prática:** `_merge_same_location` põe dentro do card da falha a boa prática que cai na mesma linha.
- `extra_analyzers.py` (`run_tsc`): `--experimentalDecorators --emitDecoratorMetadata`; ignora "nome não definido" em trecho sem imports.
- Front:
  - menu com títulos de seção maiores;
  - nenhuma barra de rolagem no site (`styles.scss`);
  - tipo de análise escolhido em verde e o outro preto;
  - "Limpar resultado" à esquerda.

## 5. Como foi validado
- **Exemplos:** cada framework ganhou um exemplo vulnerável e a versão corrigida (Java/Spring, TS/NestJS+Express, Python/Flask+FastAPI, PHP/Laravel, C#/ASP.NET Core).
- **Regras sozinhas:** acharam todas as falhas dos exemplos vulneráveis e **nada** nas versões corrigidas.
- **Pipeline do motor** (`run_sast_scan`), com o controller Spring do problema:

  | | Antes | Agora |
  |---|---|---|
  | Cards | 4 | 3 |
  | Duplicatas | 2 | 0 |
  | Falhas que faltavam | 3 | 0 |

  Os 3 cards de agora:
  - SQL Injection 11-12, com "Exposição de informação sensível" dentro;
  - Login que aceita qualquer senha 16-21, com o SQLi do login, a senha em texto puro e (no completo) a variável não usada dentro;
  - Erro não tratado na API, linha 27.
- **Versões corrigidas no pipeline:**
  - **Java, PHP, C# e TS:** 0 cards.
  - **Python:** só "nome não definido" do Ruff. O exemplo importa o Flask e usa `Usuario` e `router` sem importar; com imports no arquivo, o aviso vale.
- `ng build` e `py_compile` sem erros. Não foram escritos testes automatizados (preferência do projeto).

## 6. Limitações e riscos conhecidos
- A regra de login olha o nome do método/rota (login, signin, entrar, autenticar...). Um login com outro nome não é pego.
- Os pacotes do registro precisam de internet na hora da análise (como já era).
- Go (Gin/Echo) e Rails dependem dos pacotes `gosec` e `brakeman`, sem regra própria.

## 7. Para os slides
- A análise de código entende os frameworks que as pessoas usam (Spring, NestJS, Express, Django, Flask, FastAPI, Laravel, Rails, ASP.NET Core, Gin), não só a linguagem.
- Um problema = um card: montar o SQL e executá-lo é uma falha só, e o que acontece na mesma linha aparece junto.
- Regras próprias conferidas contra código vulnerável e corrigido: acham a falha e ficam quietas no código certo.
