"""Analisadores complementares da análise de código (todos gratuitos).

O Semgrep (+ regras do Checkop) cobre segurança em todas as linguagens. Aqui
entram as ferramentas especializadas, cada uma só quando o código enviado tem a
linguagem dela:

  sintaxe      erros de leitura do Semgrep (todas), JSON, Ruff, ESLint, PMD, ShellCheck, yamllint, actionlint, HTMLHint
  lógica       Ruff (Python), ESLint (JS/TS), PMD (Java/Apex), cppcheck (C/C++), ShellCheck, Hadolint
  segurança    Bandit (Python), ESLint + plugin security, Flawfinder (C/C++), Checkov (Terraform/K8s/CloudFormation), PMD
  dependência  OSV-Scanner (requirements.txt, go.mod, pom.xml, lockfiles...)

Todas são opcionais: sem o binário instalado a ferramenta é pulada; erro ou
tempo esgotado viram aviso, nunca derrubam a análise. A saída de cada uma é
convertida para o formato de resultado do Semgrep, para passar pela mesma
deduplicação (mesmo arquivo, linhas sobrepostas, mesma classe) e apresentação.
"""

import asyncio
import csv
import io
import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from .cvss import InvalidVectorError, base_score, rating
from .local_env import TOOLS_DIR, find_tool
from .mapping import A06
from .schemas import Finding

ANALYZER_TIMEOUT_SECONDS = int(os.getenv("SAST_ANALYZER_TIMEOUT_SECONDS", "90"))
JS_ANALYZERS_DIR = Path(os.getenv("JS_ANALYZERS_DIR") or (TOOLS_DIR / "js-analyzers"))
ESLINT_RUNNER = Path(__file__).parent / "analyzers" / "eslint_runner.mjs"

PY = (".py",)
JS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
SHELL = (".sh", ".bash")
C_CPP = (".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh")
YAML = (".yaml", ".yml")
IAC = (".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".json")
HTML = (".html", ".htm")
JAVA_APEX = (".java", ".cls", ".trigger")

# manifestos/lockfiles que o OSV-Scanner entende
DEPENDENCY_FILES = {
    "requirements.txt", "pipfile.lock", "poetry.lock", "pdm.lock", "uv.lock",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "go.mod", "go.sum", "pom.xml", "gradle.lockfile", "buildscript-gradle.lockfile",
    "composer.lock", "gemfile.lock", "cargo.lock", "packages.lock.json", "pubspec.lock",
    "mix.lock", "renv.lock",
}


def _base(name: str) -> str:
    return name.replace("\\", "/").split("/")[-1].lower()


def is_dockerfile(name: str) -> bool:
    base = _base(name)
    return base in ("dockerfile", "containerfile") or base.startswith("dockerfile.") or base.endswith(".dockerfile")


def is_workflow(name: str) -> bool:
    lower = name.replace("\\", "/").lower()
    return ".github/workflows/" in lower and lower.endswith(YAML)


def is_dependency_file(name: str) -> bool:
    base = _base(name)
    return base in DEPENDENCY_FILES or (base.startswith("requirements") and base.endswith(".txt"))


def _has(files: dict[str, str], extensions: tuple[str, ...]) -> list[str]:
    return [name for name in files if name.lower().endswith(extensions)]


@dataclass
class ExtraResult:
    # COMPLETE = todas as regras de cada ferramenta (o que for estilo/manutenção vira
    # "Boa prática"); ESSENTIAL = só bug, erro de sintaxe e falha de segurança
    complete: bool = True
    results: list[dict] = field(default_factory=list)   # formato do Semgrep
    findings: list[Finding] = field(default_factory=list)  # prontos (dependências)
    used: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def make_result(tool: str, rule: str, path: str, start: int | None, end: int | None, severity: str, message: str, *,
                category: str, cwe: str | int | None = None, title: str | None = None,
                fix: str | None = None, url: str | None = None, edits: list[dict] | None = None) -> dict:
    """Resultado no formato do Semgrep (severity: ERROR | WARNING | INFO). edits = correção
    pronta da ferramenta ({sl, sc, el, ec, text}), aplicada sobre o código enviado."""
    start = int(start or 1)
    end = int(end or start)
    return {
        "_edits": edits or [],
        "check_id": f"{tool.lower()}.{rule}",
        "path": path,
        "start": {"line": start},
        "end": {"line": max(end, start)},
        "extra": {
            "severity": severity,
            "message": message or "",
            "lines": "",
            "metadata": {
                "cwe": [f"CWE-{cwe}"] if cwe else [],
                "owasp": [],
                "checkop_tool": tool,
                "checkop_title": title,
                "checkop_fix": fix,
                "checkop_category": category,
                "checkop_url": url,
            },
        },
    }


async def _run(command: list[str], cwd: str, timeout: int = ANALYZER_TIMEOUT_SECONDS, env: dict | None = None):
    """(código de saída, stdout, stderr); código None = não executou ou estourou o tempo."""
    try:
        process = await asyncio.create_subprocess_exec(
            *command, cwd=cwd, env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except (OSError, ValueError) as error:
        return None, "", str(error)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return None, "", f"tempo limite de {timeout}s"
    return process.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def _abs(path: str, tmp_dir: str) -> str:
    # normpath: no Windows o cppcheck devolve "C:/Users/.../leak.c" (com "/"), e o mesmo arquivo
    # precisa ter o mesmo caminho que o do Semgrep para os achados se juntarem
    return os.path.normpath(path if os.path.isabs(path) else os.path.join(tmp_dir, path.lstrip("/\\")))


def _first_line(text: str) -> str:
    return (text or "").strip().splitlines()[0] if (text or "").strip() else ""


# ---------- sintaxe: Semgrep (todas as linguagens) e JSON ----------

def semgrep_syntax_results(payload: dict) -> list[dict]:
    """Erros de leitura que o Semgrep já reporta viram achados de sintaxe."""
    results = []
    for error in payload.get("errors", []):
        kind = error.get("type")
        name = kind[0] if isinstance(kind, list) and kind else kind
        if name not in ("Syntax error", "Lexical error", "PartialParsing"):
            continue
        message = error.get("message", "") or ""
        if error.get("rule_id") or "metavariable" in message.lower():
            continue  # problema numa regra, não no código do usuário
        spans = error.get("spans") or []
        if not spans and isinstance(kind, list) and len(kind) > 1 and isinstance(kind[1], list):
            spans = kind[1]
        path = error.get("path") or (spans[0].get("file") if spans and isinstance(spans[0], dict) else None)
        if not path:
            continue
        start = spans[0].get("start", {}).get("line", 1) if spans else 1
        end = spans[0].get("end", {}).get("line", start) if spans else start
        partial = name == "PartialParsing"
        results.append(make_result(
            "Semgrep", "syntax-error", path, start, end, "INFO" if partial else "WARNING",
            _first_line(message) or "Trecho que não pôde ser lido.",
            category="SYNTAX",
            title="Possível erro de sintaxe" if partial else "Erro de sintaxe",
            fix="Revise o trecho: parêntese, chave, aspas ou ponto e vírgula faltando ou sobrando costumam ser a causa.",
        ))
    return results


def json_syntax_results(tmp_dir: str, files: dict[str, str]) -> list[dict]:
    results = []
    for name, code in files.items():
        if not name.lower().endswith(".json") or not code.strip():
            continue
        try:
            json.loads(code)
        except json.JSONDecodeError as error:
            results.append(make_result(
                "Checkop", "invalid-json", _abs(name, tmp_dir), error.lineno, error.lineno, "WARNING",
                error.msg, category="SYNTAX", title="JSON inválido",
                fix="Corrija o JSON no ponto indicado (vírgula sobrando, aspas simples ou chave sem aspas são as causas mais comuns).",
            ))
    return results


# ---------- Python: Ruff (lógica/sintaxe) e Bandit (segurança) ----------

_RUFF_TITLES = {
    "F821": "Nome não definido", "F822": "Nome não definido no __all__", "F823": "Variável usada antes de ser atribuída",
    "F811": "Nome redefinido antes de ser usado", "F632": "Comparação com 'is' em valor literal",
    "F631": "assert com tupla (sempre verdadeiro)", "F701": "break fora de laço", "F702": "continue fora de laço",
    "F704": "yield fora de função", "F706": "return fora de função",
    "B006": "Argumento padrão mutável", "B007": "Variável do laço não usada", "B008": "Chamada de função como valor padrão",
    "B011": "assert False (some com -O)", "B015": "Comparação sem efeito", "B018": "Expressão sem efeito",
    "B023": "Função dentro do laço captura variável do laço", "B904": "Exceção relançada sem 'from'",
    # boa prática (o código funciona igual; é legibilidade)
    "RET501": "return None explícito desnecessário", "RET502": "return sem valor numa função que retorna valor",
    "RET503": "Falta return explícito no fim da função", "RET504": "Variável criada só para ser retornada",
    "RET505": "else desnecessário depois de return", "RET506": "else desnecessário depois de raise",
    "RET507": "else desnecessário depois de continue", "RET508": "else desnecessário depois de break",
    "SIM201": "not a == b no lugar de a != b", "SIM202": "not a != b no lugar de a == b",
    "SIM208": "Dupla negação (not not)", "SIM210": "True if cond else False no lugar de bool(cond)",
    "SIM211": "False if cond else True no lugar de not cond", "SIM212": "Condição do ternário invertida",
    "B007": "Variável do laço não usada", "B009": "getattr com nome fixo (use o atributo direto)",
    "B010": "setattr com nome fixo (atribua direto)", "B905": "zip() sem strict=",
}

# do bugbear (B), mas é estilo: o código funciona igual
_RUFF_STYLE_RULES = {"B007", "B009", "B010", "B027", "B904", "B905"}


async def run_ruff(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    binary = find_tool("ruff")
    if not _has(files, PY):
        return
    if not binary:
        out.skipped.append("Ruff")
        return
    if out.complete:
        # todas as regras, menos formatação pura e as de segurança (o Bandit cobre)
        selection = ["--select", "ALL", "--ignore", "D,E501,W291,W293,COM,Q,CPY,S"]
    else:
        selection = ["--select", "E9,F63,F7,F82,F811,B,PLE"]
    code, stdout, stderr = await _run([
        binary, "check", "--isolated", "--no-cache", "--exit-zero", "--output-format", "json", *selection, tmp_dir,
    ], tmp_dir)
    try:
        items = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        out.warnings.append(f"Ruff não pôde ser executado: {_first_line(stderr) or 'saída inválida'}")
        return
    out.used.append("Ruff")
    for item in items:
        rule = item.get("code") or "syntax-error"
        message = item.get("message", "")
        # o Ruff antigo chamava de "syntax-error"/E999; o novo, de "invalid-syntax"
        syntax = rule in ("syntax-error", "invalid-syntax") or rule.startswith("E9") or message.startswith("SyntaxError")
        if syntax:
            category, severity, title = "SYNTAX", "WARNING", "Erro de sintaxe"
        elif rule.startswith(("F82", "F7", "F63", "F811", "PLE")):
            category, severity = "LOGIC", "WARNING"
            title = _RUFF_TITLES.get(rule, f"Erro de lógica em Python ({rule})")
        elif rule.startswith(("B", "PLW", "ASYNC", "BLE", "RUF006")) and rule not in _RUFF_STYLE_RULES:
            # comportamento que costuma dar errado ao rodar (bugbear, avisos do pylint, async, except genérico)
            category, severity, title = "LOGIC", "INFO", _RUFF_TITLES.get(rule, f"Padrão propenso a bug ({rule})")
        else:  # estilo, legibilidade, simplificação, convenções (RET5, SIM2, TRY, PLC2, nomes...)
            category, severity, title = "QUALITY", "INFO", _RUFF_TITLES.get(rule, f"Boa prática em Python ({rule})")
        results_path = _abs(item.get("filename", ""), tmp_dir)
        out.results.append(make_result(
            "Ruff", rule, results_path, item.get("location", {}).get("row"), item.get("end_location", {}).get("row"),
            severity, message, category=category, title=title, url=item.get("url"),
            fix=_ruff_fix_text(item, message),
            edits=_ruff_edits(item),
        ))


def _ruff_edits(item: dict) -> list[dict]:
    """Edições que o próprio Ruff calcula para o código (mesmo as "unsafe": só são mostradas)."""
    edits = []
    for edit in ((item.get("fix") or {}).get("edits") or []):
        start, end = edit.get("location") or {}, edit.get("end_location") or {}
        if start.get("row") and end.get("row"):
            edits.append({"sl": start["row"], "sc": start.get("column", 1), "el": end["row"],
                          "ec": end.get("column", 1), "text": edit.get("content", "")})
    return edits


def _ruff_fix_text(item: dict, message: str) -> str:
    """A mensagem do Ruff já cita o nome real (`x` imported but unused); a correção dele também."""
    hint = ((item.get("fix") or {}).get("message") or "").strip()
    if hint:
        return f"{hint}. Problema apontado: {message}"
    return f"Corrija o trecho apontado: {message}"


async def run_bandit(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    binary = find_tool("bandit")
    if not _has(files, PY):
        return
    if not binary:
        out.skipped.append("Bandit")
        return
    code, stdout, stderr = await _run([binary, "-r", tmp_dir, "-f", "json", "-q", "--exit-zero"], tmp_dir)
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        out.warnings.append(f"Bandit não pôde ser executado: {_first_line(stderr) or 'saída inválida'}")
        return
    out.used.append("Bandit")
    for item in data.get("results", []):
        level = (item.get("issue_severity") or "").upper()
        if level == "LOW" and not out.complete:
            continue  # ex.: uso de assert, import de subprocess: só no modo completo
        lines = item.get("line_range") or [item.get("line_number")]
        out.results.append(make_result(
            "Bandit", item.get("test_name") or item.get("test_id", "bandit"), _abs(item.get("filename", ""), tmp_dir),
            lines[0], lines[-1], "ERROR" if level == "HIGH" else "WARNING" if level == "MEDIUM" else "INFO", item.get("issue_text", ""),
            category="SECURITY", cwe=(item.get("issue_cwe") or {}).get("id"), url=item.get("more_info"),
        ))


# ---------- JavaScript / TypeScript: ESLint (+ plugin security) ----------

_ESLINT_TITLES = {
    "no-undef": "Variável não definida", "no-unreachable": "Código inalcançável", "no-dupe-keys": "Chave duplicada no objeto",
    "no-const-assign": "Atribuição a uma constante", "no-cond-assign": "Atribuição dentro da condição",
    "no-self-assign": "Variável atribuída a ela mesma", "use-isnan": "Comparação direta com NaN",
    "valid-typeof": "typeof comparado com tipo inexistente", "no-fallthrough": "case do switch sem break",
    "no-unsafe-finally": "return/throw dentro do finally", "no-redeclare": "Variável declarada duas vezes",
    "no-constant-condition": "Condição sempre verdadeira ou falsa", "no-dupe-else-if": "else if repetido",
    "no-unsafe-negation": "Negação aplicada ao lado errado", "getter-return": "Getter sem return",
    "no-async-promise-executor": "Executor de Promise assíncrono", "no-loss-of-precision": "Número perde precisão",
    "no-func-assign": "Função sobrescrita", "no-import-assign": "Import sobrescrito", "no-dupe-args": "Parâmetro repetido",
    "no-duplicate-case": "case repetido no switch", "no-self-compare": "Valor comparado com ele mesmo",
    "no-unsafe-optional-chaining": "Encadeamento opcional usado de forma insegura", "no-sparse-arrays": "Array com buracos",
    "no-setter-return": "Setter com return", "no-class-assign": "Classe sobrescrita", "no-compare-neg-zero": "Comparação com -0",
    "no-invalid-regexp": "Expressão regular inválida", "no-obj-calls": "Objeto global chamado como função",
    "for-direction": "Laço for com direção errada (infinito)", "no-unused-labels": "Rótulo não usado",
    "array-callback-return": "Callback de map/filter/reduce sem return", "consistent-return": "Função retorna valor só em alguns caminhos",
    "eqeqeq": "== no lugar de === (conversão de tipo escondida)", "no-unused-vars": "Variável declarada e não usada",
    "prefer-const": "Variável nunca reatribuída (use const)", "no-shadow": "Variável esconde outra com o mesmo nome",
    "no-use-before-define": "Usado antes de ser definido", "no-await-in-loop": "await dentro de laço (execução em série)",
    "no-param-reassign": "Parâmetro reatribuído", "no-throw-literal": "throw de valor que não é Error",
    "require-await": "async sem await", "no-unused-expressions": "Expressão sem efeito", "no-var": "var no lugar de let/const",
    "complexity": "Função complexa demais", "max-depth": "Blocos aninhados demais", "no-empty-function": "Função vazia",
    "no-nested-ternary": "Ternário dentro de ternário", "default-case": "switch sem default", "no-alert": "alert/confirm/prompt no código",
    "no-implicit-coercion": "Conversão de tipo implícita", "radix": "parseInt sem a base", "no-else-return": "else desnecessário após return",
    "no-useless-return": "return desnecessário", "no-lonely-if": "if sozinho dentro de else", "no-unneeded-ternary": "Ternário desnecessário",
}
# regras do núcleo do ESLint que são segurança, não lógica
_ESLINT_CORE_SECURITY = {"no-eval": 95, "no-implied-eval": 95, "no-new-func": 95, "no-script-url": 79}
# "boa prática" que na verdade é bug (o modo completo liga): sobem para Lógica
_ESLINT_BUG_RULES = {
    "array-callback-return", "no-unreachable-loop", "no-self-compare", "no-template-curly-in-string",
    "no-promise-executor-return", "require-atomic-updates", "no-unmodified-loop-condition", "no-constructor-return",
    "no-use-before-define", "consistent-return", "default-case-last", "no-await-in-loop", "no-return-assign",
    "no-sequences", "radix", "guard-for-in", "no-param-reassign", "no-shadow", "@typescript-eslint/no-shadow",
    "no-throw-literal", "prefer-promise-reject-errors", "no-unused-expressions", "@typescript-eslint/no-unused-expressions",
    "@typescript-eslint/no-floating-promises", "@typescript-eslint/no-misused-promises", "@typescript-eslint/no-non-null-assertion",
}
# só estilo, mesmo estando no recommended
_ESLINT_STYLE_RULES = {"no-unused-vars", "@typescript-eslint/no-unused-vars", "@typescript-eslint/no-explicit-any",
                       "prefer-const", "no-var", "no-empty"}
_ESLINT_SECURITY_CWE = {
    "detect-eval-with-expression": 95, "detect-child-process": 78, "detect-non-literal-fs-filename": 22,
    "detect-non-literal-require": 98, "detect-unsafe-regex": 1333, "detect-non-literal-regexp": 1333,
    "detect-possible-timing-attacks": 208, "detect-pseudoRandomBytes": 338, "detect-disable-mustache-escape": 79,
    "detect-no-csrf-before-method-override": 352, "detect-buffer-noassert": 119, "detect-new-buffer": 119,
}


def _eslint_url(rule: str) -> str | None:
    if rule.startswith("security/"):
        return "https://github.com/eslint-community/eslint-plugin-security"
    if rule.startswith("@typescript-eslint/"):
        return f"https://typescript-eslint.io/rules/{rule.split('/', 1)[1]}"
    return f"https://eslint.org/docs/latest/rules/{rule}"


async def run_eslint(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    if not _has(files, JS):
        return
    node = find_tool("node")
    if not node or not (JS_ANALYZERS_DIR / "node_modules" / "eslint").is_dir():
        out.skipped.append("ESLint")
        return
    mode = "complete" if out.complete else "essential"
    code, stdout, stderr = await _run([node, str(ESLINT_RUNNER), str(JS_ANALYZERS_DIR), tmp_dir, mode], tmp_dir)
    try:
        data = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        out.warnings.append(f"ESLint não pôde ser executado: {_first_line(stderr) or 'saída inválida'}")
        return
    out.used.append("ESLint")
    for file_result in data:
        path = _abs(file_result.get("filePath", ""), tmp_dir)
        for item in file_result.get("messages", []):
            before = len(out.results)
            try:
                rule = item.get("ruleId")
                if item.get("fatal") or not rule:
                    out.results.append(make_result(
                        "ESLint", "syntax-error", path, item.get("line"), item.get("endLine"), "WARNING", item.get("message", ""),
                        category="SYNTAX", title="Erro de sintaxe",
                        fix="Corrija a sintaxe no ponto indicado; o arquivo não pode ser executado assim.",
                    ))
                    continue
                if rule.startswith("security/"):
                    short = rule.split("/", 1)[1]
                    if short == "detect-object-injection":  # só no completo: aviso fraco, muito falso positivo
                        out.results.append(make_result(
                            "ESLint", "security-detect-object-injection", path, item.get("line"), item.get("endLine"), "INFO",
                            item.get("message", ""), category="SECURITY",
                            title="Acesso a objeto com chave dinâmica (possível injeção de propriedade)", url=_eslint_url(rule),
                            fix="Se a chave vem do usuário, valide contra uma lista permitida ou use Map em vez de objeto comum.",
                        ))
                        continue
                    out.results.append(make_result(
                        "ESLint", rule.replace("/", "-"), path, item.get("line"), item.get("endLine"), "WARNING",
                        item.get("message", ""), category="SECURITY", cwe=_ESLINT_SECURITY_CWE.get(short), url=_eslint_url(rule),
                    ))
                    continue
                short = rule.split("/")[-1]
                if short in _ESLINT_CORE_SECURITY:
                    out.results.append(make_result(
                        "ESLint", rule, path, item.get("line"), item.get("endLine"), "WARNING", item.get("message", ""),
                        category="SECURITY", cwe=_ESLINT_CORE_SECURITY[short], url=_eslint_url(rule),
                    ))
                    continue
                # regra fora do recommended (modo completo) é estilo, salvo as que são bug de verdade
                quality = (item.get("category") == "QUALITY" or rule in _ESLINT_STYLE_RULES) and rule not in _ESLINT_BUG_RULES
                out.results.append(make_result(
                    "ESLint", rule.replace("/", "-").lstrip("@"), path, item.get("line"), item.get("endLine"),
                    "INFO" if quality or item.get("severity", 1) < 2 else "WARNING", item.get("message", ""),
                    category="QUALITY" if quality else "LOGIC",
                    title=_ESLINT_TITLES.get(short, f"{'Boa prática' if quality else 'Erro de lógica'} ({rule})"), url=_eslint_url(rule),
                    fix=f"Corrija o trecho apontado pelo ESLint: {item.get('message', '')}",
                ))
            finally:
                # correção pronta do ESLint (fix ou sugestão), calculada sobre o código enviado
                for added in out.results[before:]:
                    added["_edits"] = item.get("edits") or []


async def run_htmlhint(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    targets = _has(files, HTML)
    if not targets:
        return
    node = find_tool("node")
    cli = JS_ANALYZERS_DIR / "node_modules" / "htmlhint" / "bin" / "htmlhint"
    if not node or not cli.is_file():
        out.skipped.append("HTMLHint")
        return
    essential_rules = {"tag-pair", "attr-no-duplication", "id-unique", "src-not-empty", "attr-unsafe-chars"}
    all_rules = essential_rules | {
        "tagname-lowercase", "attr-lowercase", "attr-value-double-quotes", "attr-value-not-empty", "doctype-first",
        "title-require", "alt-require", "doctype-html5", "style-disabled", "inline-style-disabled", "inline-script-disabled",
        "space-tab-mixed-disabled", "id-class-ad-disabled", "head-script-disabled", "spec-char-escape",
        "empty-tag-not-self-closed", "attr-whitespace", "href-abs-or-rel",
    }
    rules = ",".join(sorted(all_rules if out.complete else essential_rules))
    code, stdout, stderr = await _run(
        [node, str(cli), "--format", "json", "--rules", rules, *[_abs(t, tmp_dir) for t in targets]], tmp_dir,
    )
    try:
        data = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        out.warnings.append(f"HTMLHint não pôde ser executado: {_first_line(stderr) or 'saída inválida'}")
        return
    out.used.append("HTMLHint")
    titles = {"tag-pair": "Tag HTML aberta e não fechada", "attr-no-duplication": "Atributo repetido na mesma tag",
              "id-unique": "id repetido na página", "src-not-empty": "src vazio", "attr-unsafe-chars": "Caractere inseguro em atributo"}
    for file_result in data if isinstance(data, list) else []:
        path = _abs(file_result.get("file", ""), tmp_dir)
        for item in file_result.get("messages", []):
            rule = (item.get("rule") or {}).get("id", "html")
            out.results.append(make_result(
                "HTMLHint", rule, path, item.get("line"), item.get("line"), "WARNING" if rule == "tag-pair" else "INFO",
                item.get("message", ""),
                category="SYNTAX" if rule == "tag-pair" else "LOGIC" if rule in essential_rules else "QUALITY",
                title=titles.get(rule, f"Problema no HTML ({rule})"), url=(item.get("rule") or {}).get("link"),
                fix="Corrija a marcação indicada para o navegador montar a página como esperado.",
            ))


# ---------- TypeScript: tsc (o que só o compilador vê) ----------

_TSC_LINE = re.compile(r"^(?P<file>.+?\.tsx?)\((?P<line>\d+),(?P<col>\d+)\): error TS(?P<code>\d+): (?P<message>.*)$")
_TSC_LOGIC = {
    "7030": "Função não retorna valor em todos os caminhos", "7027": "Código inalcançável",
    "2366": "Função não retorna valor em todos os caminhos", "2554": "Número errado de argumentos",
    "2532": "Objeto possivelmente indefinido", "2448": "Variável usada antes de ser declarada",
    "2322": "Tipo incompatível", "2345": "Argumento com tipo incompatível", "2304": "Nome não definido",
    "2367": "Comparação que nunca é verdadeira (tipos sem relação)", "2588": "Atribuição a uma constante",
    "2451": "Variável declarada duas vezes", "7029": "case do switch sem break", "2454": "Variável usada antes de ser atribuída",
    "2531": "Objeto possivelmente nulo", "18048": "Valor possivelmente indefinido", "2365": "Operador aplicado a tipos incompatíveis",
    "2362": "Operação aritmética com tipo inválido", "2349": "Chamada de algo que não é função",
}
# vem de faltar o projeto (bibliotecas, tipos do Node, tsconfig), não do código colado
_TSC_IGNORE = {"2307", "7016", "2580", "2591", "2792", "2503", "2875", "5023", "6046", "6053", "2339", "2551", "2305", "2614"}
_TS_GLOBALS = ("require", "process", "module", "exports", "__dirname", "__filename", "Buffer", "global")
# "Nome não definido" (2304) e "...você quis dizer X?" (2552): num trecho colado sem nenhum
# import, os nomes do framework (Controller, DataSource, app, bcrypt...) só faltam porque os
# imports ficaram de fora. Com imports no arquivo, o aviso continua valendo.
_TS_UNDEFINED_NAME = {"2304", "2552"}
_JS_IMPORT = re.compile(r"^\s*(import\s|export\s+.*\sfrom\s|.*\brequire\s*\()", re.M)


async def run_tsc(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    targets = _has(files, (".ts", ".tsx"))
    if not targets:
        return
    node = find_tool("node")
    tsc = JS_ANALYZERS_DIR / "node_modules" / "typescript" / "bin" / "tsc"
    if not node or not tsc.is_file():
        out.skipped.append("TypeScript")
        return
    snippets = {os.path.normcase(_abs(t, tmp_dir)) for t in targets if not _JS_IMPORT.search(files.get(t) or "")}
    code, stdout, stderr = await _run([
        node, str(tsc), "--noEmit", "--pretty", "false", "--skipLibCheck", "--noImplicitReturns",
        "--noFallthroughCasesInSwitch", "--allowUnreachableCode", "false", "--strictNullChecks",
        "--target", "es2022", "--module", "esnext", "--moduleResolution", "bundler", "--lib", "es2022,dom",
        # decorators de NestJS, Angular, TypeORM e class-validator (@Controller, @Get, @Column...):
        # sem isso o compilador acusa "erro de sintaxe" em código de framework válido
        "--experimentalDecorators", "--emitDecoratorMetadata",
        "--jsx", "preserve", *[_abs(t, tmp_dir) for t in targets],
    ], tmp_dir)
    if code is None:
        out.warnings.append(f"TypeScript não pôde ser executado: {stderr}")
        return
    out.used.append("TypeScript")
    for line in (stdout + "\n" + stderr).splitlines():
        parsed = _TSC_LINE.match(line.strip())
        if not parsed:
            continue
        number, message = parsed.group("code"), parsed.group("message")
        if number in _TSC_IGNORE or (number == "2304" and any(f"'{g}'" in message for g in _TS_GLOBALS)):
            continue
        if number in _TS_UNDEFINED_NAME and os.path.normcase(_abs(parsed.group("file"), tmp_dir)) in snippets:
            continue
        syntax = number.startswith("1") and len(number) == 4
        title = "Erro de sintaxe" if syntax else _TSC_LOGIC.get(number)
        if not title:
            if not out.complete:
                continue
            title = f"Erro de tipo (TS{number})"
        out.results.append(make_result(
            "TypeScript", f"TS{number}", _abs(parsed.group("file"), tmp_dir), parsed.group("line"), parsed.group("line"),
            "WARNING", message, category="SYNTAX" if syntax else "LOGIC", title=title,
            url=f"https://typescript.tv/errors/#ts{number}",
            fix="Corrija o ponto indicado pelo compilador do TypeScript: do jeito que está, o código quebra ou faz algo diferente do esperado.",
        ))


# ---------- C / C++: Flawfinder (segurança) e cppcheck (lógica) ----------

async def run_flawfinder(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    binary = find_tool("flawfinder")
    if not _has(files, C_CPP):
        return
    if not binary:
        out.skipped.append("Flawfinder")
        return
    minlevel = "--minlevel=0" if out.complete else "--minlevel=2"
    code, stdout, stderr = await _run([binary, "--csv", minlevel, "--dataonly", "--quiet", tmp_dir], tmp_dir)
    if code is None:
        out.warnings.append(f"Flawfinder não pôde ser executado: {stderr}")
        return
    out.used.append("Flawfinder")
    for row in csv.DictReader(io.StringIO(stdout)):
        try:
            level = int(row.get("Level") or 0)
        except ValueError:
            continue
        cwe = re.search(r"CWE-(\d+)", row.get("CWEs") or "")
        name = (row.get("Name") or "").lower()
        title = {"char": "Vetor de tamanho fixo (risco de estouro)", "memcpy": "Cópia de memória sem checar o tamanho",
                 "strlen": "strlen em texto que pode não terminar em \\0", "read": "Leitura sem checar o tamanho do buffer",
                 "rand": "Número aleatório previsível", "random": "Número aleatório previsível",
                 "getenv": "Valor de variável de ambiente usado sem validação", "access": "Checagem de arquivo sujeita a corrida (TOCTOU)",
                 "atoi": "atoi sem checar erro nem limite"}.get(name)
        message = " ".join(part for part in (row.get("Warning"), row.get("Suggestion")) if part)
        out.results.append(make_result(
            "Flawfinder", row.get("Name") or "flawfinder", _abs(row.get("File", ""), tmp_dir), row.get("Line"), row.get("Line"),
            "ERROR" if level >= 4 else "WARNING" if level == 3 else "INFO", message,
            category="SECURITY", cwe=None if title else (cwe.group(1) if cwe else None), title=title,
            url=row.get("HelpUri") or None,
            fix=row.get("Suggestion") or "Troque pela função segura equivalente e valide o tamanho da entrada.",
        ))


_CPPCHECK_TITLES = {
    "nullPointer": "Possível ponteiro nulo", "nullPointerRedundantCheck": "Ponteiro usado antes de checar se é nulo",
    "nullPointerOutOfMemory": "Retorno do malloc usado sem checar NULL", "nullPointerArithmeticOutOfMemory": "Retorno do malloc usado sem checar NULL",
    "ctunullpointerOutOfMemory": "Retorno do malloc usado sem checar NULL",
    "memleak": "Vazamento de memória", "resourceLeak": "Recurso (arquivo/handle) não liberado",
    "arrayIndexOutOfBounds": "Acesso fora dos limites do vetor", "bufferAccessOutOfBounds": "Buffer overflow",
    "uninitvar": "Variável usada sem inicializar", "doubleFree": "Memória liberada duas vezes",
    "zerodiv": "Divisão por zero", "deallocuse": "Memória usada depois de liberada", "returnDanglingLifetime": "Retorno de ponteiro para variável local",
    "syntaxError": "Erro de sintaxe", "mismatchAllocDealloc": "Alocação e liberação incompatíveis",
    "invalidPrintfArgType_s": "Formato do printf não bate com o argumento", "wrongPrintfScanfArgNum": "Número de argumentos do printf/scanf errado",
}
_CPPCHECK_IGNORE = {"missingInclude", "missingIncludeSystem", "checkersReport", "unmatchedSuppression", "toomanyconfigs",
                    "normalCheckLevelMaxBranches", "noValidConfiguration", "unknownMacro"}


async def run_cppcheck(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    binary = find_tool("cppcheck")
    if not _has(files, C_CPP):
        return
    if not binary:
        out.skipped.append("cppcheck")
        return
    enable = "--enable=all" if out.complete else "--enable=warning,performance,portability"
    code, stdout, stderr = await _run([
        binary, enable, "--inline-suppr", "--xml", "--xml-version=2", "--quiet", tmp_dir,
    ], tmp_dir)
    try:
        root = ET.fromstring(stderr or "<results/>")
    except ET.ParseError:
        out.warnings.append("cppcheck não pôde ser executado (saída inválida).")
        return
    out.used.append("cppcheck")
    for error in root.iter("error"):
        rule = error.get("id", "cppcheck")
        severity = error.get("severity", "")
        location = error.find("location")
        if rule in _CPPCHECK_IGNORE or location is None or severity == "information":
            continue
        if severity == "style" and not out.complete:
            continue
        syntax = rule in ("syntaxError", "internalAstError")
        quality = severity in ("style", "performance", "portability") and not syntax
        out.results.append(make_result(
            "cppcheck", rule, _abs(location.get("file", ""), tmp_dir), location.get("line"), location.get("line"),
            "WARNING" if severity == "error" else "INFO", error.get("msg", ""),
            category="SYNTAX" if syntax else "QUALITY" if quality else "LOGIC", cwe=None if quality else error.get("cwe"),
            title=_CPPCHECK_TITLES.get(rule, f"{'Boa prática' if quality else 'Erro de lógica'} em C/C++ ({rule})"),
            fix="Corrija o trecho indicado; em C/C++ esse tipo de erro costuma travar o programa ou corromper memória.",
        ))


# ---------- Shell: ShellCheck ----------

_SHELLCHECK_TITLES = {
    2086: "Variável sem aspas (pode quebrar ou injetar comandos)", 2046: "Substituição de comando sem aspas",
    2068: "Lista de argumentos sem aspas", 2164: "cd sem tratar falha (o script segue na pasta errada)",
    2115: "rm -rf com variável que pode estar vazia", 2155: "Declarar e atribuir na mesma linha esconde erros",
    2045: "Laço sobre a saída do ls", 2002: "cat desnecessário", 2034: "Variável atribuída e nunca usada",
    2154: "Variável usada sem ser definida", 2181: "Checagem indireta do código de saída", 2162: "read sem -r",
}


async def run_shellcheck(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    binary = find_tool("shellcheck")
    targets = _has(files, SHELL)
    if not targets:
        return
    if not binary:
        out.skipped.append("ShellCheck")
        return
    level = "style" if out.complete else "warning"
    code, stdout, stderr = await _run([binary, "-f", "json1", "-S", level, *[_abs(t, tmp_dir) for t in targets]], tmp_dir)
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        out.warnings.append(f"ShellCheck não pôde ser executado: {_first_line(stderr) or 'saída inválida'}")
        return
    out.used.append("ShellCheck")
    for item in data.get("comments", []):
        number = item.get("code", 0)
        syntax = 1000 <= number < 2000  # SC1xxx = erro de leitura do script
        # sem aspas a variável se parte em palavras e glob: quebra com espaço e permite injeção
        quality = item.get("level") in ("info", "style") and not syntax and number not in (2086, 2046, 2068, 2048, 2206, 2207)
        out.results.append(make_result(
            "ShellCheck", f"SC{number}", _abs(item.get("file", ""), tmp_dir), item.get("line"), item.get("endLine"),
            "WARNING" if item.get("level") == "error" or syntax else "INFO", item.get("message", ""),
            category="SYNTAX" if syntax else "QUALITY" if quality else "LOGIC",
            title="Erro de sintaxe no script" if syntax else _SHELLCHECK_TITLES.get(number, f"Problema no script (ShellCheck SC{number})"),
            url=f"https://www.shellcheck.net/wiki/SC{number}",
            fix="Siga a orientação do link: costuma ser colocar aspas na variável ou tratar o erro do comando.",
        ))


# ---------- Dockerfile: Hadolint ----------

_HADOLINT = {
    "DL3002": ("Último USER do Dockerfile é root", 250, "SECURITY"),
    "DL3004": ("sudo dentro do Dockerfile", 250, "SECURITY"),
    "DL3006": ("Imagem base sem versão fixa", 829, "SECURITY"),
    "DL3007": ("Imagem base com a tag latest", 829, "SECURITY"),
    "DL3020": ("ADD usado no lugar de COPY", None, "LOGIC"),
    "DL3008": ("Pacote do apt sem versão fixa", None, "LOGIC"),
    "DL3013": ("Pacote do pip sem versão fixa", None, "LOGIC"),
    "DL3016": ("Pacote do npm sem versão fixa", None, "LOGIC"),
    "DL3009": ("Cache do apt não removido", None, "LOGIC"),
    "DL3015": ("apt-get sem --no-install-recommends", None, "LOGIC"),
    "DL3025": ("CMD/ENTRYPOINT no formato shell", None, "LOGIC"),
    "DL3003": ("cd no lugar de WORKDIR", None, "LOGIC"),
    "DL4006": ("Pipe sem 'set -o pipefail' (erro escondido)", None, "LOGIC"),
    "DL3000": ("WORKDIR com caminho relativo", None, "LOGIC"),
}


async def run_hadolint(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    binary = find_tool("hadolint")
    targets = [name for name in files if is_dockerfile(name)]
    if not targets:
        return
    if not binary:
        out.skipped.append("Hadolint")
        return
    code, stdout, stderr = await _run([binary, "-f", "json", "--no-fail", *[_abs(t, tmp_dir) for t in targets]], tmp_dir)
    try:
        items = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        out.warnings.append(f"Hadolint não pôde ser executado: {_first_line(stderr) or 'saída inválida'}")
        return
    out.used.append("Hadolint")
    for item in items:
        level = item.get("level")
        if level not in ("error", "warning") and not out.complete:
            continue
        rule = item.get("code", "hadolint")
        title, cwe, category = _HADOLINT.get(rule, (f"Boa prática de Dockerfile ({rule})", None, "LOGIC"))
        if level in ("info", "style") and category != "SECURITY":
            category = "QUALITY"
        if rule.startswith("SC"):  # trecho de shell dentro do RUN, analisado pelo ShellCheck embutido
            title, category = f"Problema no comando RUN (ShellCheck {rule})", "LOGIC"
        out.results.append(make_result(
            "Hadolint", rule, _abs(item.get("file", ""), tmp_dir), item.get("line"), item.get("line"),
            "WARNING" if item.get("level") == "error" else "INFO", item.get("message", ""),
            category=category, cwe=cwe, title=None if cwe else title,
            url=f"https://github.com/hadolint/hadolint/wiki/{rule}" if rule.startswith("DL") else f"https://www.shellcheck.net/wiki/{rule}",
            fix="Siga a orientação do link para a imagem ser reproduzível e mais segura.",
        ))


# ---------- YAML e GitHub Actions: yamllint e actionlint ----------

_YAMLLINT_CONFIG = (
    "{extends: relaxed, rules: {line-length: disable, truthy: disable, document-start: disable, indentation: disable, "
    "trailing-spaces: disable, new-line-at-end-of-file: disable, empty-lines: disable, comments: disable, "
    "comments-indentation: disable, braces: disable, brackets: disable, colons: disable, commas: disable, hyphens: disable}}"
)
_YAMLLINT_LINE = re.compile(r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+): \[(?P<level>\w+)\] (?P<message>.*?)(?: \((?P<rule>[\w-]+)\))?$")


async def run_yamllint(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    binary = find_tool("yamllint")
    targets = _has(files, YAML)
    if not targets:
        return
    if not binary:
        out.skipped.append("yamllint")
        return
    config = ("{extends: default, rules: {document-start: disable, truthy: disable, line-length: {max: 160}}}"
              if out.complete else _YAMLLINT_CONFIG)
    code, stdout, stderr = await _run([binary, "-f", "parsable", "-d", config, *[_abs(t, tmp_dir) for t in targets]], tmp_dir)
    if code is None:
        out.warnings.append(f"yamllint não pôde ser executado: {stderr}")
        return
    out.used.append("yamllint")
    for line in stdout.splitlines():
        match = _YAMLLINT_LINE.match(line.strip())
        if not match or (match.group("level") != "error" and not out.complete):
            continue
        rule = match.group("rule") or "syntax"
        syntax = rule == "syntax" or "syntax error" in match.group("message").lower()
        bug = syntax or rule in ("key-duplicates", "anchors")
        out.results.append(make_result(
            "yamllint", rule, match.group("file"), match.group("line"), match.group("line"),
            "WARNING" if bug else "INFO", match.group("message"),
            category="SYNTAX" if syntax else "LOGIC" if bug else "QUALITY",
            title="YAML inválido" if syntax else ("Chave duplicada no YAML" if rule == "key-duplicates" else f"Problema no YAML ({rule})"),
            fix="Corrija o YAML no ponto indicado (indentação, dois-pontos e chaves repetidas são as causas mais comuns).",
            url=None if rule == "syntax" else f"https://yamllint.readthedocs.io/en/stable/rules.html#module-yamllint.rules.{rule.replace('-', '_')}",
        ))


async def run_actionlint(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    binary = find_tool("actionlint")
    targets = [name for name in files if is_workflow(name)]
    if not targets:
        return
    if not binary:
        out.skipped.append("actionlint")
        return
    code, stdout, stderr = await _run([binary, "-format", "{{json .}}", *[_abs(t, tmp_dir) for t in targets]], tmp_dir)
    try:
        items = json.loads(stdout or "[]") or []
    except json.JSONDecodeError:
        out.warnings.append(f"actionlint não pôde ser executado: {_first_line(stderr) or 'saída inválida'}")
        return
    out.used.append("actionlint")
    for item in items:
        kind = item.get("kind", "actionlint")
        message = item.get("message", "")
        injection = kind == "expression" and "untrusted" in message.lower()
        syntax = kind in ("syntax-check", "yaml-syntax")
        out.results.append(make_result(
            "actionlint", kind, _abs(item.get("filepath", ""), tmp_dir), item.get("line"), item.get("line"),
            "ERROR" if injection else "WARNING", message,
            category="SECURITY" if injection else "SYNTAX" if syntax else "LOGIC",
            cwe=78 if injection else None,
            title=None if injection else ("Erro de sintaxe no workflow" if syntax else f"Problema no workflow ({kind})"),
            url="https://github.com/rhysd/actionlint/blob/main/docs/checks.md",
            fix="Corrija o workflow no ponto indicado; dados do evento (título de PR, branch) nunca devem entrar direto num run:.",
        ))


# ---------- Infraestrutura como código: Checkov ----------

# modo completo: todos os formatos de infraestrutura que o Checkov entende
_CHECKOV_COMPLETE = ",".join([
    "terraform", "terraform_json", "kubernetes", "kustomize", "cloudformation", "helm", "github_actions", "dockerfile",
    "arm", "bicep", "serverless", "openapi", "ansible", "gitlab_ci", "azure_pipelines", "bitbucket_pipelines",
    "circleci_pipelines", "argo_workflows",
])


async def run_checkov(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    binary = find_tool("checkov")
    dockerfiles = out.complete and any(is_dockerfile(name) for name in files)
    if not dockerfiles and (not _has(files, IAC) or all(is_dependency_file(name) for name in _has(files, IAC))):
        return
    if not binary:
        out.skipped.append("Checkov")
        return
    # no Windows o pip cria checkov.cmd, que chama o python do PATH (sem o Checkov instalado):
    # roda pelo python do próprio ambiente das ferramentas
    venv_python = Path(binary).with_name("python.exe")
    launcher = [str(venv_python), "-m", "checkov.main"] if binary.lower().endswith(".cmd") and venv_python.is_file() else [binary]
    code, stdout, stderr = await _run([
        *launcher, "-d", tmp_dir, "-o", "json", "--quiet", "--compact", "--skip-download",
        "--framework", _CHECKOV_COMPLETE if out.complete else "terraform,kubernetes,cloudformation,helm,github_actions",
    ], tmp_dir, timeout=max(ANALYZER_TIMEOUT_SECONDS, 150))
    # saída vazia com erro = o Checkov não rodou (não é "nenhum problema encontrado")
    error_lines = (stderr or "").strip().splitlines()
    if code is None or (not (stdout or "").strip() and error_lines):
        out.warnings.append(f"Checkov não pôde ser executado: {error_lines[-1] if error_lines else 'sem resposta'}")
        return
    try:
        data = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        out.warnings.append(f"Checkov não pôde ser executado: {_first_line(stderr) or 'saída inválida'}")
        return
    out.used.append("Checkov")
    reports = data if isinstance(data, list) else [data]
    for report in reports:
        for item in (report.get("results") or {}).get("failed_checks", []) if isinstance(report, dict) else []:
            lines = item.get("file_line_range") or [1, 1]
            level = (item.get("severity") or "").upper()
            out.results.append(make_result(
                "Checkov", item.get("check_id", "checkov"), _abs(item.get("file_path", ""), tmp_dir), lines[0], lines[-1],
                "ERROR" if level in ("HIGH", "CRITICAL") else "WARNING", item.get("check_name", ""),
                category="SECURITY",
                # o nome da verificação diz o que está errado ("S3 bucket ... public READ access"); vai traduzido
                title=f"{(item.get('check_name') or 'Configuração insegura').rstrip('.')} ({item.get('check_id', 'Checkov')})",
                url=item.get("guideline"),
                fix="Ajuste o recurso conforme o guia indicado (restringir acesso, ligar criptografia, não rodar como root...).",
            ))


# ---------- Java / Apex: PMD ----------

_PMD_RULESETS = ",".join([
    "category/java/errorprone.xml", "category/java/security.xml", "category/java/multithreading.xml",
    "category/apex/errorprone.xml", "category/apex/security.xml",
])
# regras do errorprone que são mais estilo que bug (falso positivo demais num trecho colado)
_PMD_NOISY = {
    "AvoidLiteralsInIfCondition", "AvoidFieldNameMatchingMethodName", "AvoidFieldNameMatchingTypeName", "NullAssignment",
    "AvoidDuplicateLiterals", "ReturnEmptyCollectionRatherThanNull", "MissingSerialVersionUID", "NonSerializableClass",
    "TestClassWithoutTestCases", "UseLocaleWithCaseConversions", "UseProperClassLoader", "AssignmentInOperand",
    "AvoidBranchingStatementAsLastInLoop", "AvoidCatchingGenericException", "DoNotTerminateVM", "UseConcurrentHashMap",
    "AvoidUsingVolatile", "DoNotUseThreads", "AvoidSynchronizedAtMethodLevel", "AvoidSynchronizedStatement",
    "ApexCSRF",
}
# opinião de estilo, sem relação com bug ou risco (e sem sentido num trecho colado):
# ficam de fora até no modo completo
_PMD_TRIVIA = {
    "LocalVariableCouldBeFinal", "MethodArgumentCouldBeFinal", "SystemPrintln", "CommentRequired", "CommentSize",
    "CommentDefaultAccessModifier", "NoPackage", "AtLeastOneConstructor", "OnlyOneReturn", "ShortVariable", "LongVariable",
    "ShortMethodName", "ShortClassName", "UseUnderscoresInNumericLiterals", "VariableDeclarationUsageDistance",
    "TooFewBranchesForSwitch", "UseExplicitTypes", "LawOfDemeter", "DataClass", "UseVarargs", "AvoidFinalLocalVariable",
    "CallSuperInConstructor", "UnnecessaryLocalBeforeReturn", "ConfusingTernary", "LinguisticNaming",
    "UnnecessaryFullyQualifiedName", "UseUtilityClass", "ClassNamingConventions", "LocalVariableNamingConventions",
    "FormalParameterNamingConventions", "FieldNamingConventions", "MethodNamingConventions", "UnnecessaryModifier",
    "UnnecessaryImport", "UselessParentheses", "PrematureDeclaration", "LooseCoupling", "AvoidUsingShortType",
    "UnnecessaryBoxing", "UnnecessaryCast", "UseDiamondOperator", "ControlStatementBraces", "UnnecessaryReturn",
    "AvoidPrintStackTrace", "GuardLogStatement", "TooManyStaticImports", "AvoidDollarSigns", "EmptyControlStatement",
    "ApexDoc", "AvoidGlobalModifier", "TypeNameMismatch", "LocalVariableDeclarationShouldBeAtStartOfBlock",
    "UseLocaleWithCaseConversions", "FieldDeclarationsShouldBeAtStartOfClass", "LongVariable",
}
_PMD_TITLES = {
    "NonExhaustiveSwitch": "switch sem default", "UnusedLocalVariable": "Variável local não usada", "UnusedPrivateMethod": "Método privado não usado",
    "UnusedPrivateField": "Campo privado não usado", "UnusedFormalParameter": "Parâmetro não usado",
    "UnusedAssignment": "Valor atribuído e nunca usado", "StringInstantiation": "new String() desnecessário",
    "AvoidReassigningParameters": "Parâmetro reatribuído", "SwitchStmtsShouldHaveDefault": "switch sem default",
    "CyclomaticComplexity": "Método complexo demais", "CognitiveComplexity": "Método difícil de entender",
    "NPathComplexity": "Caminhos demais no método", "GodClass": "Classe faz coisas demais", "ExcessiveParameterList": "Parâmetros demais",
    "AvoidDeeplyNestedIfStmts": "if aninhado demais", "SimplifyBooleanReturns": "Retorno booleano pode ser simplificado",
    "UseStringBufferForStringAppends": "Concatenação de String em laço", "AvoidInstantiatingObjectsInLoops": "Objeto criado dentro do laço",
    "ForLoopCanBeForeach": "for pode virar for-each", "PreserveStackTrace": "Exceção relançada sem a causa original",
    "EmptyCatchBlock": "Exceção engolida (catch vazio)", "CloseResource": "Recurso não fechado",
    "CompareObjectsWithEquals": "Objetos comparados com == em vez de equals", "UseEqualsToCompareStrings": "Strings comparadas com ==",
    "ReturnFromFinallyBlock": "return dentro do finally", "MisplacedNullCheck": "Checagem de null no lugar errado",
    "BrokenNullCheck": "Checagem de null quebrada", "EqualsNull": "equals(null) sempre falso",
    "ImplicitSwitchFallThrough": "case do switch sem break", "JumbledIncrementer": "Variável errada incrementada no laço",
    "UnconditionalIfStatement": "if sempre verdadeiro ou falso", "AvoidCatchingNPE": "NullPointerException capturada",
    "DoNotThrowExceptionInFinally": "Exceção lançada dentro do finally", "ConstructorCallsOverridableMethod": "Construtor chama método sobrescrevível",
    "AvoidDecimalLiteralsInBigDecimalConstructor": "BigDecimal criado com double (perde precisão)",
    "SingleMethodSingleton": "Singleton com mais de um getInstance", "ProperCloneImplementation": "clone() mal implementado",
    "AvoidInstanceofChecksInCatchClause": "instanceof dentro do catch", "DontImportSun": "Import de classes internas sun.*",
    "OnDemandImport": "Import com * (pacote inteiro)",
}


# modo completo: todas as categorias de regras do PMD, de Java e de Apex
_PMD_ALL = ",".join(
    f"category/{language}/{category}.xml"
    for language in ("java", "apex")
    for category in ("bestpractices", "codestyle", "design", "documentation", "errorprone", "multithreading", "performance", "security")
)


def _pmd_command(binary: str, tmp_dir: str, complete: bool = False) -> list[str]:
    return [binary, "check", "--dir", tmp_dir, "--rulesets", _PMD_ALL if complete else _PMD_RULESETS, "--format", "json",
            "--no-progress", "--no-fail-on-violation", "--no-cache"]


async def run_pmd(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    binary = find_tool("pmd")
    if not _has(files, JAVA_APEX):
        return
    if not binary:
        out.skipped.append("PMD")
        return
    code, stdout, stderr = await _run(_pmd_command(binary, tmp_dir, out.complete), tmp_dir, timeout=max(ANALYZER_TIMEOUT_SECONDS, 120))
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        out.warnings.append(f"PMD não pôde ser executado: {_first_line(stderr) or 'saída inválida'}")
        return
    out.used.append("PMD")
    for file_result in data.get("files", []):
        path = _abs(file_result.get("filename", ""), tmp_dir)
        for item in file_result.get("violations", []):
            rule = item.get("rule", "pmd")
            priority = int(item.get("priority", 3))
            if rule in _PMD_TRIVIA or (not out.complete and (rule in _PMD_NOISY or priority > 3)):
                continue
            ruleset = (item.get("ruleset") or "").lower().replace(" ", "")
            security = ruleset == "security"
            bug = ruleset in ("errorprone", "multithreading") and rule not in _PMD_NOISY
            cwe = {"HardCodedCryptoKey": 321, "InsecureCryptoIv": 329, "ApexSOQLInjection": 89, "ApexXSSFromURLParam": 79,
                   "ApexOpenRedirect": 601, "ApexInsecureEndpoint": 319, "ApexSharingViolations": 284}.get(rule)
            out.results.append(make_result(
                "PMD", rule, path, item.get("beginline"), item.get("endline"),
                # bug de verdade é Médio; o "priority" do PMD mede importância de estilo, não de risco
                "WARNING" if bug or security or cwe else "INFO",
                item.get("description", ""), category="SECURITY" if security or cwe else "LOGIC" if bug else "QUALITY", cwe=cwe,
                title=None if cwe else _PMD_TITLES.get(rule, f"{'Erro de lógica' if bug else 'Boa prática'} ({rule})"),
                url=item.get("externalInfoUrl"),
                fix=_PMD_FIX.get(rule, f"{item.get('description', '').rstrip('.')}. Os detalhes e um exemplo corrigido estão no link da regra."),
            ))
    for error in data.get("processingErrors", []):
        raw = _first_line(error.get("message", ""))
        # "ParseException: Parse exception in file '...\tmpXYZ\Busca.java' at line 16, column 9: Encountered int"
        where = re.search(r"line (\d+)", raw)
        found = re.search(r"Encountered:?\s*(.+?)(?:\.\s*$|$)", raw)
        message = f"O PMD não conseguiu ler o arquivo a partir deste ponto (encontrou {found.group(1).strip()})." if found             else "O PMD não conseguiu ler o arquivo a partir deste ponto."
        out.results.append(make_result(
            "PMD", "syntax-error", _abs(error.get("filename", ""), tmp_dir), int(where.group(1)) if where else 1, None, "WARNING",
            message, category="SYNTAX", title="Erro de sintaxe",
            fix="Corrija a sintaxe (o erro costuma estar na linha anterior, como um ; faltando); enquanto isso, as regras do PMD não rodam neste arquivo.",
        ))


_PMD_FIX = {
    "OnDemandImport": (
        "Importe só as classes que o arquivo usa (ex.: import org.springframework.web.bind.annotation.RestController;). "
        "O * traz o pacote inteiro: esconde de onde vem cada classe e pode dar conflito quando dois pacotes têm "
        "classes com o mesmo nome. A IDE faz isso sozinha (Organize Imports: Ctrl+Shift+O no Eclipse/VS Code, "
        "Ctrl+Alt+O no IntelliJ)."
    ),
    "CompareObjectsWithEquals": "Compare o conteúdo com a.equals(b) (ou Objects.equals(a, b), que aceita null). O == compara se é o mesmo objeto na memória, não se o valor é igual.",
    "UseEqualsToCompareStrings": "Use texto1.equals(texto2) (ou equalsIgnoreCase). Com ==, duas Strings iguais criadas separadamente dão false.",
    "ImplicitSwitchFallThrough": "Termine cada case com break (ou return). Se a continuação for de propósito, deixe um comentário // fallthrough.",
    "EmptyCatchBlock": "Trate a exceção ou registre no log; um catch vazio esconde o erro e o programa segue em estado inválido.",
    "CloseResource": "Abra o recurso com try-with-resources: try (var conn = ...) { ... } fecha sozinho, mesmo com exceção.",
    "ReturnFromFinallyBlock": "Tire o return do finally: ele descarta a exceção que estava sendo lançada.",
    "MisplacedNullCheck": "Cheque se é null antes de usar o objeto, não depois.",
    "BrokenNullCheck": "Use && (e não ||) na checagem: if (x != null && x.metodo()).",
    "EqualsNull": "Use x == null; x.equals(null) é sempre false e lança NPE se x for null.",
    "JumbledIncrementer": "O laço interno incrementa a variável do laço externo: confira a variável do i++.",
    "UnconditionalIfStatement": "A condição é sempre verdadeira ou falsa: remova o if ou corrija a condição.",
    "AvoidCatchingNPE": "Evite o NullPointerException checando null antes, em vez de capturá-lo.",
    "UnusedLocalVariable": "Remova a variável ou use o valor; sobra de código costuma esconder um bug.",
    "UnusedAssignment": "O valor atribuído é sobrescrito antes de ser lido: confira se a atribuição certa é a outra.",
    "StringInstantiation": "Use o literal direto (String s = \"Java\"); new String(...) cria um objeto a mais sem necessidade.",
    "SwitchStmtsShouldHaveDefault": "Inclua um default para tratar valores inesperados.",
    "PreserveStackTrace": "Ao relançar, passe a exceção original como causa: throw new MinhaException(\"msg\", e).",
    "UseStringBufferForStringAppends": "Monte o texto com StringBuilder: concatenar String num laço cria um objeto novo a cada volta.",
    "HardCodedCryptoKey": "Não deixe a chave no código: carregue de um cofre de segredos ou variável de ambiente.",
}


# ---------- Java: javac (o que só o compilador vê) ----------

_JAVAC_LINE = re.compile(r"^(?P<file>.+?\.java):(?P<line>\d+): (?P<kind>error|warning): (?P<message>.*)$")
_PUBLIC_TYPE = re.compile(r"^\s*public\s+(?:(?:final|abstract|sealed|non-sealed|static|strictfp)\s+)*(?:class|interface|enum|record|@interface)\s+(\w+)", re.M)
# erro que vem de faltar a biblioteca/arquivo (o trecho colado não traz o projeto), não do código
_JAVAC_MISSING_CONTEXT = ("does not exist", "cannot find symbol", "cannot access", "is public, should be declared in a file named",
                          "bad class file", "class file for", "location:", "symbol:")
_JAVAC_LOGIC = {
    "might not have been initialized": "Variável usada sem ser inicializada",
    "missing return statement": "Método sem return em algum caminho",
    "unreachable statement": "Código inalcançável",
    "possible lossy conversion": "Conversão com perda de dados",
    "incompatible types": "Tipos incompatíveis",
    "might already have been assigned": "Variável final atribuída duas vezes",
    "is already defined": "Nome declarado duas vezes",
    "unreported exception": "Exceção não tratada nem declarada",
    "non-static": "Membro de instância usado em contexto estático",
}


async def run_javac(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    """Compila cada .java sozinho e aponta o que o compilador acusa no próprio código."""
    sources = [name for name in files if name.lower().endswith(".java")]
    if not sources:
        return
    binary = find_tool("javac")
    if not binary:
        out.skipped.append("javac")
        return
    import tempfile
    used = False
    for name in sources:
        code_text = files[name]
        # o javac exige o arquivo com o nome da classe pública; o nome enviado é arbitrário
        match = _PUBLIC_TYPE.search(code_text)
        with tempfile.TemporaryDirectory() as work:
            src = os.path.join(work, f"{match.group(1)}.java" if match else os.path.basename(name))
            with open(src, "w", encoding="utf-8", newline="") as handle:
                handle.write(code_text)
            outdir = os.path.join(work, "out")
            os.makedirs(outdir)
            code, stdout, stderr = await _run(
                [binary, "-Xlint:all", "-Xmaxerrs", "100", "-Xmaxwarns", "100", "-encoding", "UTF-8", "-proc:none", "-d", outdir, src],
                work,
            )
        if code is None:
            out.warnings.append(f"javac não pôde ser executado: {stderr}")
            return
        used = True
        for line in (stderr + "\n" + stdout).splitlines():
            parsed = _JAVAC_LINE.match(line.strip())
            if not parsed:
                continue
            message = parsed.group("message")
            if any(marker in message for marker in _JAVAC_MISSING_CONTEXT):
                continue
            if parsed.group("kind") == "warning":
                if "[fallthrough]" in message:
                    title, category, severity = "case do switch sem break", "LOGIC", "WARNING"
                elif "[divzero]" in message:
                    title, category, severity = "Divisão por zero", "LOGIC", "WARNING"
                elif "[deprecation]" in message or "[removal]" in message:
                    title, category, severity = "Uso de API obsoleta", "QUALITY", "INFO"
                elif not out.complete:
                    continue
                else:
                    title, category, severity = f"Aviso do compilador ({message.split(']')[0].lstrip('[')})", "QUALITY", "INFO"
            else:
                logic = next((label for marker, label in _JAVAC_LOGIC.items() if marker in message), None)
                title, category, severity = (logic, "LOGIC", "WARNING") if logic else ("Erro de compilação", "SYNTAX", "WARNING")
            out.results.append(make_result(
                "javac", re.sub(r"[^a-z]+", "-", title.lower()).strip("-"), _abs(name, tmp_dir),
                parsed.group("line"), parsed.group("line"), severity, message, category=category, title=title,
                fix="Corrija o ponto indicado pelo compilador: do jeito que está, o código não compila ou falha ao rodar.",
            ))
    if used:
        out.used.append("javac")


# ---------- dependências: OSV-Scanner ----------

def _version_key(version: str) -> tuple:
    return tuple(int(part) if part.isdigit() else -1 for part in re.split(r"[.\-+]", version or "0"))


def _line_of(content: str, package: str) -> int:
    for number, line in enumerate(content.splitlines(), start=1):
        if package.lower() in line.lower():
            return number
    return 1


def _cvss_of(vulnerability: dict) -> tuple[float | None, str | None]:
    best = (None, None)
    for item in vulnerability.get("severity", []) or []:
        vector = item.get("score", "")
        if not str(vector).startswith("CVSS:3"):
            continue
        try:
            score = base_score(vector)
        except InvalidVectorError:
            continue
        if best[0] is None or score > best[0]:
            best = (score, vector)
    return best


async def run_osv(tmp_dir: str, files: dict[str, str], out: ExtraResult) -> None:
    manifests = [name for name in files if is_dependency_file(name)]
    if not manifests:
        return
    binary = find_tool("osv-scanner")
    if not binary:
        out.skipped.append("OSV-Scanner")
        return
    code, stdout, stderr = await _run([binary, "scan", "source", "-r", "--format", "json", tmp_dir], tmp_dir)
    if code not in (0, 1):
        out.warnings.append("OSV-Scanner não conseguiu consultar a base de vulnerabilidades (precisa de internet).")
        return
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        out.warnings.append("OSV-Scanner devolveu uma saída inválida.")
        return
    out.used.append("OSV-Scanner")
    by_path = {os.path.normcase(_abs(name, tmp_dir)): (name, code_) for name, code_ in files.items()}
    for result in data.get("results", []) or []:
        source = (result.get("source") or {}).get("path", "")
        relative, content = by_path.get(os.path.normcase(source), (_base(source), ""))
        for package_entry in result.get("packages", []) or []:
            package = package_entry.get("package") or {}
            name, version = package.get("name", "?"), package.get("version", "?")
            vulnerabilities = package_entry.get("vulnerabilities") or []
            if not vulnerabilities:
                continue
            scores = [_cvss_of(v) for v in vulnerabilities]
            score, vector = max((s for s in scores if s[0] is not None), default=(None, None), key=lambda s: s[0])
            cves = [alias for v in vulnerabilities for alias in [v.get("id", ""), *(v.get("aliases") or [])] if alias.startswith("CVE-")]
            fixed = sorted({
                event["fixed"]
                for v in vulnerabilities for affected in v.get("affected", []) or []
                if (affected.get("package") or {}).get("name", "").lower() == name.lower()
                for rng in affected.get("ranges", []) or [] for event in rng.get("events", []) or [] if event.get("fixed")
            }, key=_version_key)
            listed = "\n".join(
                f"- {v.get('id')}" + (f" ({', '.join(a for a in v.get('aliases') or [] if a.startswith('CVE-'))})" if any(
                    a.startswith('CVE-') for a in v.get('aliases') or []) else "") + f": {v.get('summary') or 'sem resumo'}"
                for v in vulnerabilities[:10]
            )
            more = f"\n... e mais {len(vulnerabilities) - 10}." if len(vulnerabilities) > 10 else ""
            direct = bool(content) and name.lower() in content.lower()
            line = _line_of(content, name)
            kind = "Dependência vulnerável" if direct else "Dependência indireta vulnerável"
            out.findings.append(Finding(
                title=f"{kind}: {name} {version} ({relative}:{line})",
                description=f"{len(vulnerabilities)} vulnerabilidade(s) conhecida(s) em {name} {version} "
                            f"({package.get('ecosystem', '')}):\n{listed}{more}"
                            + ("" if direct else f"\n\n{name} não está no arquivo: é puxada por outra dependência listada."),
                severity=rating(score) if score is not None else "MEDIUM",
                tool="SAST",
                ruleId=f"osv-scanner.{name}",
                affectedUrl=f"{relative}:{line}",
                cveId=cves[0] if cves else None,
                cvssScore=score,
                cvssVector=vector,
                cvssSource="TEMPLATE" if vector else None,
                rawResponse="\n".join(content.splitlines()[line - 1:line]) if content else None,
                remediation=(f"Atualize {name} para a versão {fixed[-1]} ou mais nova." if fixed
                             else f"Ainda não há versão corrigida de {name}: avalie trocar a biblioteca ou mitigar o uso.")
                            + "\n\nReferências: " + " ".join(f"https://osv.dev/vulnerability/{v.get('id')}" for v in vulnerabilities[:3]),
                owaspUrl=A06,
                category="DEPENDENCY",
                detectedBy=["OSV-Scanner"],
            ))


# ---------- orquestração ----------

ANALYZERS = (run_javac, run_tsc, run_ruff, run_bandit, run_eslint, run_htmlhint, run_flawfinder, run_cppcheck, run_shellcheck,
             run_hadolint, run_yamllint, run_actionlint, run_checkov, run_pmd, run_osv)


async def run_extra_analyzers(tmp_dir: str, files: dict[str, str], complete: bool = True) -> ExtraResult:
    """Roda em paralelo as ferramentas das linguagens presentes. Nunca lança erro."""
    out = ExtraResult(complete=complete, results=json_syntax_results(tmp_dir, files))
    if out.results:
        out.used.append("Checkop (JSON)")

    async def guarded(analyzer):
        try:
            await analyzer(tmp_dir, files, out)
        except Exception as error:  # uma ferramenta com problema não derruba as outras
            out.warnings.append(f"{analyzer.__name__.removeprefix('run_')} falhou: {error}")

    await asyncio.gather(*(guarded(analyzer) for analyzer in ANALYZERS))
    return out
