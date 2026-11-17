import asyncio
import json
import os
import re
import shutil
import tempfile
import time

from .schemas import Finding
from .mapping import map_to_owasp_category
from .translator import translate_many
from .cwe_catalog import cwe_numbers, describe
from .secrets_runner import dedupe_findings, run_gitleaks

SEMGREP_BINARY = shutil.which("semgrep")
SAST_TIMEOUT_SECONDS = int(os.getenv("SAST_TIMEOUT_SECONDS", "120"))

# Pacotes oficiais do registro do Semgrep, mantidos pela comunidade e válidos para
# todas as linguagens que ele suporta. Juntos cobrem bem mais que o "auto"
# (que também exige métricas ligadas). Ajustável por variável de ambiente.
SAST_RULESETS = [
    r.strip()
    for r in os.getenv("SAST_RULESETS", "p/default,p/security-audit,p/secrets,p/owasp-top-ten").split(",")
    if r.strip()
]

# Regras próprias do Checkop: cobrem o que o registro gratuito deixa passar
# (Rust, Kotlin, Scala, C#, Swift, PHP, shell, Dockerfile, Terraform, HTML).
# Medido num corpus de código vulnerável: +24 falhas detectadas, 0 falso positivo
# no corpus equivalente seguro. Ficam no repositório, sem depender de internet.
CHECKOP_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules", "checkop")
if os.path.isdir(CHECKOP_RULES_DIR):
    SAST_RULESETS.append(CHECKOP_RULES_DIR)

SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}

REMEDIATION_SUGGESTIONS = {
    "sqli": "Use consultas parametrizadas (prepared statements) em vez de concatenar/interpolar a entrada do usuário na query.",
    "sql-injection": "Use consultas parametrizadas (prepared statements) em vez de concatenar/interpolar a entrada do usuário na query.",
    "xss": "Faça escape/sanitização da saída antes de inserir no HTML, ou use um template engine que escapa por padrão.",
    "command-injection": "Evite montar comandos de shell a partir de entrada do usuário; use APIs que não passem por um shell (ex.: execFile em vez de exec).",
    "path-traversal": "Valide e normalize o caminho recebido, restringindo a um diretório base conhecido (allowlist).",
    "hardcoded-secret": "Remova o segredo do código-fonte e carregue por variável de ambiente ou um cofre de segredos.",
    "eval": "Evite eval()/Function() com entrada do usuário; use parsers seguros (ex.: JSON.parse) para o caso de uso real.",
    "deserialization": "Evite desserializar dados não confiáveis; use formatos seguros (JSON) com validação de schema.",
    "ssrf": "Valide o destino da requisição contra uma allowlist de hosts/IPs permitidos antes de fazer a chamada.",
}



class SastExecutionError(Exception):
    pass


def _suggest_fix(check_id: str) -> str:
    lowered = check_id.lower()
    for key, suggestion in REMEDIATION_SUGGESTIONS.items():
        if key in lowered:
            return suggestion
    return "Revise o trecho apontado conforme a mensagem da regra e a documentação da categoria OWASP relacionada."


def _safe_relative_path(filename: str) -> str | None:
    # mantém subpastas (evita colisão de index.js) e descarta "..", "." e "/" iniciais
    parts = [p for p in filename.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or None


def _relative_to(path: str, base_dir: str) -> str:
    # o Semgrep devolve o caminho dentro da pasta temporária; mostramos só o nome enviado.
    # Sempre com "/": no Windows vinha "\" e arquivos em subpastas (.github/workflows/ci.yml)
    # não casavam com o nome enviado (sem trecho de código na tela).
    if path.startswith(base_dir):
        path = path[len(base_dir):]
    return path.replace("\\", "/").lstrip("/")


def _extract_snippet(content: str | None, start: int | None, end: int | None) -> str:
    # sem login no Semgrep o campo "lines" vem como "requires login"; lemos do código enviado
    if not content or not start:
        return ""
    return "\n".join(content.splitlines()[start - 1:(end or start)])


def _rule_name(check_id: str) -> str:
    return check_id.split(".")[-1].replace("-", " ").capitalize() or "Problema de segurança"


_SEVERITY_RANK = {"ERROR": 3, "WARNING": 2, "INFO": 1}


# Classe da falha: decide quando duas regras falam da MESMA vulnerabilidade.
# Primeiro pelo nome da regra (alguns pacotes trazem CWE errado nos metadados,
# ex.: "tainted-sql-string" marcada como CWE-915), depois pela família do CWE.
_CLASS_BY_RULE_NAME = [
    ("sqli", re.compile(r"sql|sqli|jdbc|query-injection", re.I)),
    ("xss", re.compile(r"xss|cross-site-scripting|innerhtml|raw-html|html-output|dangerouslysetinnerhtml", re.I)),
    ("integrity", re.compile(r"curl-pipe|pipe-download|download-to-shell|wget-pipe", re.I)),
    ("cmd", re.compile(r"command-injection|os-command|shell-injection|subprocess|child-process|exec-detected|spawn-shell|shell-eval", re.I)),
    ("path", re.compile(r"path-traversal|directory-traversal|dynamic-include|file-inclusion|\blfi\b", re.I)),
    ("ssrf", re.compile(r"ssrf|server-side-request", re.I)),
    ("deserialization", re.compile(r"deserializ|pickle|marshal|unserialize|yaml-load|readobject", re.I)),
    ("redirect", re.compile(r"open-redirect|redirect", re.I)),
    ("crypto", re.compile(r"weak-hash|password-hash|md5|sha1|insecure-hash|weak-crypto|des-|ecb", re.I)),
    ("secret", re.compile(r"hardcoded|hard-coded|secret|password|credential|api-key|private-key", re.I)),
]

_CLASS_BY_CWE = {
    "sqli": {"89", "564", "943"},
    "cmd": {"78", "77"},
    "code": {"94", "95", "917", "1336"},
    "xss": {"79", "80"},
    "path": {"22", "23", "73", "98"},
    "ssrf": {"918"},
    "deserialization": {"502"},
    "redirect": {"601"},
    "secret": {"798", "259", "321"},
    "crypto": {"327", "328", "916", "326"},
    "integrity": {"494"},
    "unpinned": {"829", "1357", "1104"},
    "tls": {"295"},
}

# CWE usada para título/correção quando a classe veio do nome da regra
CLASS_CANONICAL_CWE = {
    "sqli": "89", "cmd": "78", "code": "94", "xss": "79", "path": "22", "ssrf": "918",
    "deserialization": "502", "redirect": "601", "secret": "798", "crypto": "327",
    "integrity": "494", "tls": "295",
}


def vulnerability_class(result: dict) -> str:
    rule = result.get("check_id", "").split(".")[-1]
    for name, pattern in _CLASS_BY_RULE_NAME:
        if pattern.search(rule):
            return name
    cwes = cwe_numbers(result.get("extra", {}).get("metadata", {}).get("cwe"))
    for name, family in _CLASS_BY_CWE.items():
        if any(cwe in family for cwe in cwes):
            return name
    return f"cwe-{cwes[0]}" if cwes else rule


def _span(result: dict) -> tuple[int, int]:
    start = result.get("start", {}).get("line") or 0
    return start, result.get("end", {}).get("line") or start


def _dedupe_results(results: list[dict]) -> list[dict]:
    """Uma falha por (arquivo, classe, trecho). Regras de pacotes diferentes que
    apontam a mesma vulnerabilidade em linhas iguais ou sobrepostas (ex.: SQLi
    marcado nas linhas 8-11 por uma e na 11 por outras quatro) viram um achado
    só: o mais grave e, empatando, o de trecho mais preciso."""
    buckets: dict[tuple, list[list[dict]]] = {}
    for result in sorted(results, key=_span):
        key = (result.get("path"), vulnerability_class(result))
        groups = buckets.setdefault(key, [])
        start, end = _span(result)
        for group in groups:
            g_start = min(_span(r)[0] for r in group)
            g_end = max(_span(r)[1] for r in group)
            if start <= g_end and end >= g_start:  # linhas sobrepostas
                group.append(result)
                break
        else:
            groups.append([result])

    unique = []
    for groups in buckets.values():
        for group in groups:
            best = max(
                group,
                key=lambda r: (_SEVERITY_RANK.get(r.get("extra", {}).get("severity"), 0), -(_span(r)[1] - _span(r)[0])),
            )
            unique.append({**best, "_rule_count": len({r.get("check_id") for r in group}), "_class": vulnerability_class(best)})
    return unique


def _parse_result(result: dict, base_dir: str, contents: dict[str, str], translations: dict[str, str]) -> Finding:
    extra = result.get("extra", {})
    severity = SEVERITY_MAP.get(extra.get("severity", "INFO"), "LOW")
    metadata = extra.get("metadata", {})
    cwe_ids = metadata.get("cwe") or []
    owasp_tags = metadata.get("owasp") or []

    tags = [str(t) for t in (owasp_tags if isinstance(owasp_tags, list) else [owasp_tags])]
    owasp_category = map_to_owasp_category(tags, cwe_ids if isinstance(cwe_ids, list) else [cwe_ids])

    file_path = _relative_to(result.get("path", "arquivo"), base_dir)
    line = result.get("start", {}).get("line")
    end_line = result.get("end", {}).get("line")
    snippet = extra.get("lines", "")
    if not snippet or snippet == "requires login":
        snippet = _extract_snippet(contents.get(file_path), line, end_line)
    check_id = result.get("check_id", "")
    rule_name = _rule_name(check_id)
    message = extra.get("message", "")

    # título e correção pela classe da falha, não pelo nome técnico da regra. O CWE da
    # regra vale quando é da mesma classe (ex.: 98 = inclusão de arquivo, mais preciso
    # que o 22 genérico); senão entra o CWE da classe (metadados às vezes vêm errados)
    rule_cwes = cwe_numbers(cwe_ids)
    klass = result.get("_class", "")
    family = _CLASS_BY_CWE.get(klass, set())
    matching = [c for c in rule_cwes if c in family]
    canonical = CLASS_CANONICAL_CWE.get(klass)
    preferred = matching or ([canonical] if canonical else rule_cwes)
    known = describe(preferred + rule_cwes)
    title = known[0] if known else translations.get(rule_name, rule_name)
    remediation = known[1] if known else _suggest_fix(check_id)
    description = translations.get(message, message)
    if result.get("_rule_count", 1) > 1:
        description = f"{description}\n\nConfirmado por {result['_rule_count']} regras diferentes."

    return Finding(
        title=f"{title} ({file_path}:{line})",
        description=description,
        severity=severity,
        tool="SAST",
        affectedUrl=f"{file_path}:{line}" + (f"-{end_line}" if end_line and end_line != line else ""),
        cveId=None,
        cvssScore=None,
        rawRequest=None,
        rawResponse=snippet,
        remediation=remediation,
        owaspUrl=owasp_category,
    )


async def run_sast_scan(files: dict[str, str], language: str = "pt-BR") -> tuple[list[Finding], float]:
    """files: {"nome_do_arquivo.js": "conteúdo do código", ...}"""
    if not SEMGREP_BINARY:
        raise SastExecutionError("Binário 'semgrep' não encontrado no PATH do motor Python.")

    started_at = time.monotonic()

    with tempfile.TemporaryDirectory() as tmp_dir:
        for filename, content in files.items():
            relative_name = _safe_relative_path(filename)  # evita path traversal no próprio upload
            if relative_name is None:
                raise SastExecutionError(f"Nome de arquivo inválido: {filename!r}")
            destination = os.path.join(tmp_dir, relative_name)
            try:
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                with open(destination, "w", encoding="utf-8") as f:
                    f.write(content)
            except OSError as err:
                raise SastExecutionError(f"Não foi possível gravar {filename!r}: {err}") from err

        command = [
            SEMGREP_BINARY,
            *(f"--config={ruleset}" for ruleset in SAST_RULESETS),
            "--json",
            "--quiet",
            "--metrics=off",  # o código do usuário nunca sai da máquina; só as regras são baixadas
            tmp_dir,
        ]

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SAST_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise SastExecutionError(f"O Semgrep excedeu o tempo limite de {SAST_TIMEOUT_SECONDS}s.")

        duration = time.monotonic() - started_at

        try:
            payload = json.loads(stdout.decode(errors="replace") or "{}")
        except json.JSONDecodeError:
            raise SastExecutionError(stderr.decode(errors="replace") or "Falha ao interpretar a saída do Semgrep.")

        results = payload.get("results", [])

        # 0 = sem achados, 1 = achados. Qualquer outro código sem resultado é falha real
        # (ex.: sem internet para baixar as regras do --config=auto) e não pode virar "código limpo".
        if process.returncode not in (0, 1) and not results:
            error_messages = "; ".join(e.get("message", "") for e in payload.get("errors", []) if e.get("message"))
            detail = stderr.decode(errors="replace").strip() or error_messages
            raise SastExecutionError(detail or f"O Semgrep terminou com código {process.returncode}.")

        results = _dedupe_results(results)
        contents = {_safe_relative_path(name): code for name, code in files.items()}
        texts = {_rule_name(r.get("check_id", "")) for r in results}
        texts |= {r.get("extra", {}).get("message", "") for r in results}
        translations = await translate_many(texts, language)

        findings = [_parse_result(r, tmp_dir, contents, translations) for r in results]
        # segredos fixos (chaves, tokens) em qualquer linguagem; ainda dentro da pasta temporária
        findings += await run_gitleaks(tmp_dir, contents)
        duration = time.monotonic() - started_at
        return dedupe_findings(findings), duration