import asyncio
import json
import shutil
import time

from .mapping import (
    INTRUSIVE_TAGS,
    fallback_cvss_for_severity,
    map_to_owasp_category,
    resolve_cvss_score,
)

from .schemas import Finding

NUCLEI_BINARY = shutil.which("nuclei")

SEVERITY_MAP = {
    "info": "INFO",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}


class NucleiNotInstalledError(Exception):
    pass


class NucleiExecutionError(Exception):
    pass


def _build_command(target_url: str, safe_mode: bool, rate_limit: int) -> list[str]:
    if not NUCLEI_BINARY:
        raise NucleiNotInstalledError(
            "Binário 'nuclei' não encontrado no PATH deste servidor. "
            "Instale em https://github.com/projectdiscovery/nuclei antes de rodar varreduras."
        )

    command = [
        NUCLEI_BINARY,
        "-target", target_url,
        "-jsonl",             
        "-silent",
        "-nc",                 
        "-rate-limit", str(rate_limit),  # RF-51 / RNF-15
        "-timeout", "10",
        "-include-rr",         (RF-49)
    ]

    if safe_mode:
        # RF-52
        command += ["-etags", ",".join(INTRUSIVE_TAGS)]

    return command


def _parse_line(raw_line: str) -> Finding | None:
    raw_line = raw_line.strip()
    if not raw_line:
        return None

    try:
        entry = json.loads(raw_line)
    except json.JSONDecodeError:
        return None

    info = entry.get("info", {}) or {}
    classification = info.get("classification") or {}
    severity = SEVERITY_MAP.get((info.get("severity") or "info").lower(), "INFO")

    cvss_score = resolve_cvss_score(classification)
    if cvss_score is None:
        cvss_score = fallback_cvss_for_severity(info.get("severity"))

    cve_ids = classification.get("cve-id") or []
    cve_id = cve_ids[0] if cve_ids else None

    references = info.get("reference") or []
    owasp_url = references[0] if references else None

    request_response = entry.get("request"), entry.get("response")

    return Finding(
        title=info.get("name") or entry.get("template-id") or "Achado do Nuclei",
        description=info.get("description"),
        severity=severity,
        tool="NUCLEI",
        affectedUrl=entry.get("matched-at") or entry.get("host"),
        cveId=cve_id,
        cvssScore=cvss_score,
        rawRequest=request_response[0],
        rawResponse=request_response[1],
        remediation=info.get("remediation"),
        owaspUrl=owasp_url or map_to_owasp_category(entry.get("tags") or []),
    )


async def run_nuclei_scan(target_url: str, safe_mode: bool, rate_limit: int) -> tuple[list[Finding], float]:
    command = _build_command(target_url, safe_mode, rate_limit)
    started_at = time.monotonic()

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    duration = time.monotonic() - started_at

    if process.returncode != 0 and not stdout:
        raise NucleiExecutionError(stderr.decode(errors="replace") or "Falha ao executar o Nuclei.")

    findings = []
    for line in stdout.decode(errors="replace").splitlines():
        finding = _parse_line(line)
        if finding:
            findings.append(finding)

    return findings, duration


def update_templates() -> None:
    if not NUCLEI_BINARY:
        raise NucleiNotInstalledError("Binário 'nuclei' não encontrado no PATH.")
    # RF-45
    import subprocess
    subprocess.run([NUCLEI_BINARY, "-update-templates"], check=True, capture_output=True)