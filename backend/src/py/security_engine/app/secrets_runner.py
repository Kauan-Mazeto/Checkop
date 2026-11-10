"""Detecção de segredos fixos no código com o Gitleaks (open-source, MIT).

Complementa o Semgrep: o Gitleaks reconhece centenas de formatos de credencial
(chaves de nuvem, tokens de API, JWT, chaves privadas...) em qualquer linguagem
ou arquivo. Falha aqui nunca derruba a análise: sem o binário, ou com erro,
devolvemos lista vazia e o Semgrep segue sozinho.
"""

import asyncio
import json
import os

from .cwe_catalog import CWE_INFO
from .local_env import find_tool
from .mapping import map_to_owasp_category
from .schemas import Finding

GITLEAKS_BINARY = find_tool("gitleaks")
GITLEAKS_TIMEOUT_SECONDS = int(os.getenv("GITLEAKS_TIMEOUT_SECONDS", "60"))
_TITLE, _FIX = CWE_INFO["798"]


def _relative(path: str, base_dir: str) -> str:
    normalized = path.replace("\\", "/")
    base = base_dir.replace("\\", "/").rstrip("/") + "/"
    return normalized[len(base):] if normalized.startswith(base) else normalized.split("/")[-1]


def parse_gitleaks_report(report: list[dict], base_dir: str, contents: dict[str, str]) -> list[Finding]:
    findings = []
    for leak in report:
        file_path = _relative(leak.get("File", "arquivo"), base_dir)
        line = leak.get("StartLine") or 1
        end_line = leak.get("EndLine") or line
        source = contents.get(file_path) or ""
        snippet = "\n".join(source.splitlines()[line - 1:end_line]) if source else (leak.get("Match") or "")
        kind = leak.get("Description") or leak.get("RuleID") or "segredo"
        findings.append(
            Finding(
                title=f"{_TITLE} ({file_path}:{line})",
                description=f"Foi encontrado um segredo do tipo \"{kind}\" escrito diretamente no código. "
                "Qualquer pessoa com acesso ao código ou ao repositório consegue usá-lo.",
                severity="HIGH",
                tool="SAST",
                ruleId=f"gitleaks.{leak.get('RuleID', 'secret')}",
                affectedUrl=f"{file_path}:{line}" + (f"-{end_line}" if end_line != line else ""),
                rawResponse=snippet,
                remediation=_FIX,
                owaspUrl=map_to_owasp_category([], ["CWE-798"]),
            )
        )
    return findings


async def run_gitleaks(scan_dir: str, contents: dict[str, str]) -> list[Finding]:
    if not GITLEAKS_BINARY:
        return []
    command = [
        GITLEAKS_BINARY, "dir", scan_dir,
        "--no-banner", "--report-format", "json", "--report-path", "-",
        "--exit-code", "0",
        "--redact",  # o valor do segredo não vai para o relatório nem para logs
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=GITLEAKS_TIMEOUT_SECONDS)
        report = json.loads(stdout.decode(errors="replace") or "[]")
    except (OSError, asyncio.TimeoutError, json.JSONDecodeError):
        return []
    return parse_gitleaks_report(report if isinstance(report, list) else [], scan_dir, contents)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Semgrep (p/secrets) e Gitleaks podem acusar o mesmo segredo: um por (local, categoria)."""
    seen: set[tuple[str, str]] = set()
    unique = []
    for finding in findings:
        location = (finding.affectedUrl or "").split("-")[0]
        category = finding.title.split(" (")[0]
        key = (location, category)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
