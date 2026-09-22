import asyncio
import json
import shutil
import time

from .schemas import Finding

SUBFINDER_BINARY = shutil.which("subfinder")


class SubfinderNotInstalledError(Exception):
    pass


class SubfinderExecutionError(Exception):
    pass


async def run_subdomain_enum(domain: str) -> tuple[list[Finding], float]:
    if not SUBFINDER_BINARY:
        raise SubfinderNotInstalledError(
            "Binário 'subfinder' não encontrado no PATH. Instale em "
            "https://github.com/projectdiscovery/subfinder antes de usar este objetivo."
        )

    command = [SUBFINDER_BINARY, "-d", domain, "-silent", "-json"]
    started_at = time.monotonic()

    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    duration = time.monotonic() - started_at

    if process.returncode != 0 and not stdout:
        raise SubfinderExecutionError(stderr.decode(errors="replace") or "Falha ao executar o Subfinder.")

    findings = []
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = entry.get("host")
        if not host:
            continue

        findings.append(
            Finding(
                title=f"Subdomínio encontrado: {host}",
                description=f"Fonte: {entry.get('source', 'desconhecida')}",
                severity="INFO",
                tool="SUBFINDER",
                affectedUrl=host,
            )
        )

    return findings, duration