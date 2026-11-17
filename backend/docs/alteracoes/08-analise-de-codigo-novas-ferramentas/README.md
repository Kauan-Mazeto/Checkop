# 08 — Análise de código: novas ferramentas e medição de acerto

**Data:** 2026-11-17 · **Status:** Proposto (não iniciado) · **Requisitos:** espec.txt 3.2 (análise de código), RF-21 (correção sugerida)

## 1. Problema
A análise de código usa hoje o **Semgrep** (pacotes oficiais + regras próprias em `rules/checkop`) e o **Gitleaks** (segredos). Ela funciona por **padrão de código**, então:

- deixa passar falhas em que a entrada do usuário atravessa várias variáveis ou funções antes de chegar ao ponto perigoso;
- não verifica **dependências** vulneráveis (`package.json`, `requirements.txt` etc.), uma das maiores fontes de falha real;
- quase não acusa **erros de lógica** comuns (variável indefinida, código inalcançável, bug de script), só falhas de segurança;
- não tem um número que diga **quanto ela acerta** (cobertura e falsos positivos), o que o TCC precisa para sustentar a qualidade.

Nenhuma ferramenta estática chega a 100%. O objetivo é **cobrir mais e medir**.

O ponto de partida já medido: num conjunto de 19 arquivos vulneráveis, o Semgrep gratuito achou 54 linhas, as regras do Checkop acrescentaram 24, e houve 0 falso positivo no conjunto seguro equivalente. Os testes estão em `src/py/security_engine/tests/test_checkop_rules.py`.

## 2. Proposta
Integrar ao motor (`run_sast_scan`) analisadores especializados. Cada um roda **só para as linguagens que ele cobre**, e todos são **opcionais**: sem o binário instalado, a análise segue com o resto e mostra um aviso.

### Ordem recomendada
| # | Item | Ganho | Esforço |
|---|---|---|---|
| 1 | **SCA de dependências** (OSV-Scanner) | Alto: libs com CVE, quase sem falso positivo | Baixo |
| 2 | **Medição de acerto** (benchmark) | Números para o TCC | Médio |
| 3 | Analisadores por linguagem (tabela abaixo) | Médio/alto | Médio |
| 4 | Regras do Checkop em **modo taint** do Semgrep | Médio | Médio |
| 5 | CodeQL (opcional) | Alto, porém pesado | Alto |

### Ferramentas por linguagem
| Linguagem / área | Ferramenta | Pega | Como instalar no Windows | Saída usada |
|---|---|---|---|---|
| Dependências (JS, Python, Java, Go, PHP, Ruby, .NET, Rust...) | **OSV-Scanner** v2 | bibliotecas com CVE conhecida e a versão corrigida | binário `osv-scanner_windows_amd64.exe` (releases do GitHub google/osv-scanner) | `scan source -r --format json` |
| Python | **Bandit** | falhas de segurança específicas de Python | pip | `-r <dir> -f json -q` |
| Python | **Ruff** | erros de lógica (nome indefinido, variável não usada, regras *bugbear*) | pip | `check --output-format json --select F,B,E9` |
| JavaScript / TypeScript | **ESLint** + `eslint-plugin-security` + `typescript-eslint` | erros de lógica (código inalcançável, chave duplicada...) e padrões inseguros | `npm install` numa pasta própria em `tools/eslint` (o Node já existe) | `--format json` |
| Go | **gosec** | falhas de segurança em Go | binário `gosec_*_windows_amd64.tar.gz` (releases securego/gosec) | `-fmt=json` |
| C / C++ | **Flawfinder** | funções perigosas, buffer overflow (com CWE) | pip | `--csv` ou `--sarif` |
| C / C++ | **cppcheck** | erros de lógica: ponteiro nulo, vazamento de memória, acesso fora do vetor | instalador MSI (cppcheck.sourceforge.io); tentar extração sem admin com `msiexec /a` | `--xml` |
| Shell | **ShellCheck** | bugs de script (aspas, variáveis) e injeção | zip `shellcheck-vX.zip` (releases koalaman/shellcheck) | `-f json1` |
| Dockerfile | **Hadolint** | boas práticas e falhas de imagem | binário `hadolint-windows-x86_64.exe` | `-f json` |
| Terraform, Kubernetes, CloudFormation, Helm | **Checkov** | configuração insegura de nuvem e contêiner | pip | `-d <dir> -o json --quiet --compact` |
| Ruby on Rails | **Brakeman** | falhas de segurança em Rails | precisa de Ruby (não instalado) | `-f json` |
| Várias (lógica entre funções e arquivos) | **CodeQL** | fluxo de dados completo | CLI + pacotes (~1 GB) | SARIF |

### Fora do escopo desta alteração
- Ferramentas pagas ou que exigem conta (Semgrep Pro, Snyk, SonarQube Cloud).
- Erros de **lógica de negócio** (ex.: IDOR, usuário A vendo dado do B). Ferramenta estática não sabe a regra; o teste dinâmico do ZAP e a revisão humana cobrem.

## 3. Decisões tomadas
| Decisão | Opções consideradas | Escolha e motivo |
|---|---|---|
| Onde instalar as ferramentas Python | pip global; venv próprio | **venv em `backend/tools/pyanalyzers`**: o Checkov traz muitas dependências e pode quebrar as do Semgrep (instalado no Python global). |
| Como juntar os resultados | lista separada por ferramenta; formato único | **Converter cada saída para o formato de resultado do Semgrep** (`check_id`, `path`, `start`, `end`, `extra.severity`, `extra.metadata.cwe`) e passar pelo mesmo `_dedupe_results` + `_parse_result`. Assim a deduplicação por arquivo, linhas sobrepostas e classe de vulnerabilidade já junta a mesma falha vista por duas ferramentas. Exceção: OSV-Scanner gera o `Finding` direto (título com pacote, versão e CVE). |
| Achado de lógica sem CWE (ShellCheck, Ruff, ESLint) | descartar; título genérico | Novo campo opcional `metadata.checkop_title` lido por `_parse_result` (ex.: "Erro de script (ShellCheck SC2086)"), com a mensagem traduzida na descrição. |
| Ruído | tudo; só severidade alta | Descartar o nível mais baixo de cada ferramenta (ex.: Bandit LOW, ShellCheck *style*, Hadolint *info*), para não afogar o usuário. Revisar depois com o benchmark. |
| CodeQL | integrar já; adiar | **Adiar**: a licença gratuita cobre pesquisa acadêmica e código aberto, não um serviço comercial fechado. Também exige compilar o projeto em linguagens compiladas e tem cerca de 1 GB. |
| Brakeman | instalar Ruby; pular | **Pular por enquanto**: exige Ruby no servidor; o Semgrep já cobre Ruby razoavelmente. |
| gosec | instalar o Go portátil em `tools/go`; pular | gosec **precisa do Go** para carregar os pacotes. Instalar o zip portátil (`go1.x.windows-amd64.zip`) e passar o caminho no PATH do processo. |

## 4. O que precisa ser implementado
1. **Instalação** (pasta `backend/tools/`, fora do git):
   - `pyanalyzers/` (venv): `pip install bandit ruff flawfinder checkov`. **O venv já foi criado em 2026-11-17, mas a instalação dos pacotes foi interrompida:** dá para reaproveitar ou apagar e criar de novo.
   - `osv-scanner/osv-scanner.exe`, `hadolint/hadolint.exe`, `gosec/gosec.exe`, `shellcheck/shellcheck.exe`, `go/` (portátil), `eslint/` (npm), `cppcheck/` (MSI extraído).
   - Ajustar `local_env.find_tool` para procurar também em `tools/pyanalyzers/Scripts/<nome>.exe` e em `tools/eslint/node_modules/.bin/eslint.cmd`.
2. **Motor** (`src/py/security_engine/app/`):
   - Criar `extra_analyzers.py`, com uma entrada por ferramenta: linguagens/extensões, comando, tempo limite e um conversor da saída para o formato do Semgrep.
   - Em `run_sast_scan`, rodar em paralelo (`asyncio.gather`) só os analisadores das linguagens presentes nos arquivos enviados, cada um com tempo limite próprio e sem derrubar a análise se falhar (mesmo padrão do `secrets_runner.py`).
   - Criar `sca_runner.py` para o OSV-Scanner. A severidade sai do vetor CVSS da vulnerabilidade com `cvss.base_score`; o CVE vai em `cveId` e a versão corrigida na correção.
   - Novas CWEs no `cwe_catalog.py`, como a **1395** ("Dependência com vulnerabilidade conhecida").
   - Mapa CWE por regra para quem não informa CWE, como Hadolint (DL3002 → CWE-250, DL3007 → CWE-829) e ShellCheck (SC2086 → CWE-78 quando a variável vem de fora).
   - Mostrar em cada achado **quais ferramentas confirmaram** ("Detectado por: Semgrep, Bandit").
3. **Regras em modo taint**: reescrever, *além* das atuais, as regras do Checkop para Kotlin, C# e PHP com `mode: taint` (origem: parâmetros da requisição; destino: SQL, comando, `include`), cobrindo entrada que passa por variáveis. Medir antes e depois com o conjunto de teste.
4. **Benchmark de acerto**:
   - Script `benchmark/` no motor que roda a análise sobre um conjunto rotulado e calcula cobertura e taxa de falso positivo.
   - Conjuntos: o corpus interno (vulnerável e seguro, já existe nos testes); o **OWASP Benchmark** (Java, gera a nota automaticamente); a **Juliet Test Suite** do NIST (C/C++/Java); e o código-fonte do Juice Shop, DVWA e WebGoat.
5. **Front-end**: aceitar os arquivos de dependência no upload (`package.json`, `package-lock.json`, `requirements.txt`, `poetry.lock`, `pom.xml`, `go.mod`, `go.sum`, `composer.lock`, `Gemfile.lock`, `Cargo.lock`) e mostrar a ferramenta de origem no achado.
6. **Documentos legais**: o OSV-Scanner consulta a base pública **osv.dev**, enviando só nomes e versões de pacotes, nunca o código. Incluir isso na Política de Privacidade (seção de fornecedores).

## 5. Como validar
- Para cada ferramenta, um teste com um trecho vulnerável e um seguro, como em `test_checkop_rules.py` (pulado se o binário não estiver instalado).
- Rodar os 19 exemplos da tela (`code-view.ts`) e o corpus completo antes e depois, comparando o total de achados e os falsos positivos.
- Benchmark: registrar cobertura e falso positivo de cada etapa nesta pasta (`resultados.md`).

## 6. Limitações e riscos conhecidos
- O tempo de análise cresce com cada ferramenta: rodar em paralelo e manter tempo limite por ferramenta.
- O OSV-Scanner precisa de internet para consultar a base de vulnerabilidades.
- Algumas ferramentas não têm versão nativa para Windows ou exigem runtime extra (Brakeman/Ruby, gosec/Go). No servidor de produção (Linux), a instalação é mais simples.
- Mais ferramentas podem trazer mais falso positivo; o benchmark serve para calibrar o que entra.

## 7. Para os slides
- Análise de código com várias ferramentas especializadas, uma por linguagem, além do Semgrep.
- Verificação de dependências vulneráveis (SCA), com CVE e a versão que corrige.
- Achados de várias ferramentas unificados: a mesma falha aparece uma vez, com quem a confirmou.
- Acerto medido em benchmarks públicos (OWASP Benchmark, Juliet), com cobertura e taxa de falso positivo.
