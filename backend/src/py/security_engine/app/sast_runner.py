import asyncio
import json
import os
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
    # o Semgrep devolve o caminho dentro da pasta temporária; mostramos só o nome enviado
    if path.startswith(base_dir):
        return path[len(base_dir):].lstrip("/\\")
    return path


def _extract_snippet(content: str | None, start: int | None, end: int | None) -> str:
    # sem login no Semgrep o campo "lines" vem como "requires login"; lemos do código enviado
    if not content or not start:
        return ""
    return "\n".join(content.splitlines()[start - 1:(end or start)])


def _rule_name(check_id: str) -> str:
    return check_id.split(".")[-1].replace("-", " ").capitalize() or "Problema de segurança"


_SEVERITY_RANK = {"ERROR": 3, "WARNING": 2, "INFO": 1}


def _dedupe_results(results: list[dict]) -> list[dict]:
    """Uma falha por (arquivo, linha, CWE). Pacotes diferentes costumam ter regras
    distintas para a mesma falha (ex.: duas regras de SQL Injection na mesma linha);
    mantemos a mais grave e anotamos quantas regras concordaram."""
    groups: dict[tuple, list[dict]] = {}
    for result in results:
        cwes = cwe_numbers(result.get("extra", {}).get("metadata", {}).get("cwe"))
        key = (result.get("path"), result.get("start", {}).get("line"), cwes[0] if cwes else result.get("check_id"))
        groups.setdefault(key, []).append(result)

    unique = []
    for group in groups.values():
        best = max(group, key=lambda r: _SEVERITY_RANK.get(r.get("extra", {}).get("severity"), 0))
        unique.append({**best, "_rule_count": len(group)})
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

    # título e correção pela classe da falha (CWE), não pelo nome técnico da regra
    known = describe(cwe_numbers(cwe_ids))
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


async def run_sast_scan(files: dict[str, str]) -> tuple[list[Finding], float]:
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
        translations = await translate_many(texts)

        findings = [_parse_result(r, tmp_dir, contents, translations) for r in results]
        # segredos fixos (chaves, tokens) em qualquer linguagem; ainda dentro da pasta temporária
        findings += await run_gitleaks(tmp_dir, contents)
        duration = time.monotonic() - started_at
        return dedupe_findings(findings), duration