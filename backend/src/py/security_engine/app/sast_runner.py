import asyncio
import json
import os
import shutil
import tempfile
import time

from .schemas import Finding
from .mapping import map_to_owasp_category

SEMGREP_BINARY = shutil.which("semgrep")
SAST_TIMEOUT_SECONDS = int(os.getenv("SAST_TIMEOUT_SECONDS", "120"))

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


def _parse_result(result: dict) -> Finding:
    extra = result.get("extra", {})
    severity = SEVERITY_MAP.get(extra.get("severity", "INFO"), "LOW")
    metadata = extra.get("metadata", {})
    cwe_ids = metadata.get("cwe", [])
    owasp_tags = metadata.get("owasp", [])

    tags = [str(t) for t in owasp_tags] if owasp_tags else []
    owasp_category = map_to_owasp_category(tags, cwe_ids if isinstance(cwe_ids, list) else [cwe_ids])

    file_path = result.get("path", "arquivo")
    line = result.get("start", {}).get("line")
    end_line = result.get("end", {}).get("line")
    snippet = extra.get("lines", "")
    check_id = result.get("check_id", "")

    return Finding(
        title=f"{check_id.split('.')[-1].replace('-', ' ').title()} ({file_path}:{line})",
        description=extra.get("message", ""),
        severity=severity,
        tool="SAST",
        affectedUrl=f"{file_path}:{line}" + (f"-{end_line}" if end_line and end_line != line else ""),
        cveId=None,
        cvssScore=None,
        rawRequest=None,
        rawResponse=snippet,
        remediation=_suggest_fix(check_id),
        owaspUrl=owasp_category,
    )


async def run_sast_scan(files: dict[str, str]) -> tuple[list[Finding], float]:
    """files: {"nome_do_arquivo.js": "conteúdo do código", ...}"""
    if not SEMGREP_BINARY:
        raise SastExecutionError("Binário 'semgrep' não encontrado no PATH do motor Python.")

    started_at = time.monotonic()

    with tempfile.TemporaryDirectory() as tmp_dir:
        for filename, content in files.items():
            safe_name = os.path.basename(filename)  # evita path traversal no próprio upload
            with open(os.path.join(tmp_dir, safe_name), "w", encoding="utf-8") as f:
                f.write(content)

        command = [SEMGREP_BINARY, "--config=auto", "--json", "--quiet", tmp_dir]

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

        findings = [_parse_result(r) for r in payload.get("results", [])]
        return findings, duration