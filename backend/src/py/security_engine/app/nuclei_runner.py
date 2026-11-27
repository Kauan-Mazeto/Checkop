import asyncio
import json
import os
import re
import time
from urllib.parse import urlsplit

from .cvss import score_finding
from .evidence import mark_evidence
from .mapping import (
    INTRUSIVE_TAGS,
    map_to_owasp_category,
    resolve_cvss_score,
)

from .local_env import find_tool
from .schemas import Finding

NUCLEI_BINARY = find_tool("nuclei")

# Protege contra um scan que trava e nunca libera o processo (ex.: alvo que
# aceita conexão mas nunca responde). Ajustável por variável de ambiente.
NUCLEI_TIMEOUT_SECONDS = int(os.getenv("NUCLEI_TIMEOUT_SECONDS", "900"))

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


def _build_command(target_url: str, safe_mode: bool, rate_limit: int, tags: list[str] | None = None) -> list[str]:
    if not NUCLEI_BINARY:
        raise NucleiNotInstalledError(
            "Binário 'nuclei' não encontrado no PATH deste servidor. "
            "Instale em https://github.com/projectdiscovery/nuclei antes de rodar varreduras."
        )

    command = [
        NUCLEI_BINARY,
        "-target", target_url,
        "-jsonl",
        "-nc",
        "-duc",  # sem checagem de atualização a cada varredura (RF-45 cuida disso)
        # DNS do sistema como fallback: sem isso o Nuclei não resolve "localhost"
        # nem nomes do arquivo hosts/rede interna, descarta o alvo como "fora do ar"
        # e termina sem achados e sem erro
        "-sr",
        "-rate-limit", str(rate_limit),  # RF-51 / RNF-15
        "-timeout", "10",
        "-include-rr",  # RF-49
    ]

    if tags:
        command += ["-tags", ",".join(tags)]

    # RF-51: templates de negação de serviço nunca rodam, nem com opt-in de ataque
    command += ["-etags", ",".join(INTRUSIVE_TAGS if safe_mode else ["dos"])]

    return command

def _as_list(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(item) for item in value]


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

    cve_ids = _as_list(classification.get("cve-id"))
    cve_id = cve_ids[0] if cve_ids else None

    # as tags do Nuclei ficam em info.tags (não no topo da linha)
    tags = _as_list(info.get("tags"))
    cwe_ids = _as_list(classification.get("cwe-id"))
    references = _as_list(info.get("reference"))

    # nota CVSS 3.1: vetor do template (NVD para CVEs) > vetor da classe (CWE) > severidade
    cvss = score_finding(severity, classification.get("cvss-metrics"), cwe_ids)
    if cvss["cvssSource"] == "SEVERITY" and resolve_cvss_score(classification) is not None:
        # template com nota mas sem vetor: vale a nota publicada pelo autor
        cvss = {**cvss, "cvssScore": resolve_cvss_score(classification), "cvssSource": "TEMPLATE"}

    # templates quase nunca trazem "remediation"; as referências vão em campo próprio
    # (links clicáveis na tela), não coladas no texto da correção (RF-21)
    remediation = info.get("remediation")
    reference_urls = [str(r).strip() for r in references if str(r).strip().startswith(("http://", "https://"))]

    # como o Nuclei concluiu: o template só reporta quando o matcher bate na resposta.
    # Em inglês, como o resto do texto das ferramentas (a tradução é feita na leitura).
    template_id = entry.get("template-id") or "template"
    matcher = entry.get("matcher-name")
    extracted = [str(x) for x in _as_list(entry.get("extracted-results"))][:3]
    detection = f'The Nuclei template "{template_id}" matched the response'
    if matcher:
        detection += f' (matcher "{matcher}")'
    detection += "."
    if extracted:
        detection += " Captured value: " + ", ".join(extracted) + "."

    # o que o template capturou (versão, segredo, caminho...) marcado onde aparece:
    # na resposta, ou na requisição quando a prova está nela
    response, request = entry.get("response"), entry.get("request")
    for extracted in _as_list(entry.get("extracted-results")):
        response, found = mark_evidence(response, str(extracted))
        if not found:
            request, found = mark_evidence(request, str(extracted))
        if found:
            break

    return Finding(
        title=info.get("name") or entry.get("template-id") or "Achado do Nuclei",
        description=info.get("description"),
        severity=cvss["severity"],
        tool="NUCLEI",
        ruleId=entry.get("template-id"),
        affectedUrl=entry.get("matched-at") or entry.get("host"),
        cveId=cve_id,
        cvssScore=cvss["cvssScore"],
        cvssVector=cvss["cvssVector"],
        cvssSource=cvss["cvssSource"],
        # o Nuclei só reporta quando o matcher do template bate na resposta
        confidence="CONFIRMED" if severity != "INFO" else None,
        # o Nuclei já devolve o comando curl equivalente à requisição que confirmou a falha
        reproduction=entry.get("curl-command"),
        rawRequest=request,
        rawResponse=response,
        remediation=remediation,
        detection=detection,
        references="\n".join(dict.fromkeys(reference_urls[:5])) or None,
        owaspUrl=map_to_owasp_category(tags, cwe_ids),  # RF-47
    )

def _target_hostport(target_url: str) -> tuple[str, str]:
    """("localhost", "localhost:3000") do alvo, com a porta padrão quando a URL não traz."""
    parsed = urlsplit(target_url)
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, f"{host}:{port}"


_SKIPPED_HOST = re.compile(r"Skipped\s+(\S+)\s+from target list as found unresponsive", re.IGNORECASE)
_NO_ADDRESS = re.compile(r"no address found for host\s*[\"']?([^\s\"']+)", re.IGNORECASE)


def unreachable_warning(stderr: str, target_url: str) -> str | None:
    """O Nuclei descarta o alvo que não responde e sai com código 0: vira aviso.

    Só vale para o PRÓPRIO alvo: vários templates testam outras portas do mesmo host
    (ex.: localhost:5814/autopass de um produto específico); porta fechada ali é o
    esperado e não quer dizer que o site está fora do ar.
    """
    host, hostport = _target_hostport(target_url)
    skipped = {match.lower() for match in _SKIPPED_HOST.findall(stderr)}
    unresolved = {match.lower().rstrip(".:") for match in _NO_ADDRESS.findall(stderr)}
    if hostport not in skipped and host not in unresolved:
        return None
    return (
        "O Nuclei não conseguiu acessar o alvo e foi interrompido; os achados dele podem estar faltando. "
        "Confira se o site está no ar e acessível a partir do servidor do Checkop."
    )


async def run_nuclei_scan(
    target_url: str, safe_mode: bool, rate_limit: int, tags: list[str] | None = None,
    cancel: asyncio.Event | None = None,
) -> tuple[list[Finding], float, list[str]]:
    command = _build_command(target_url, safe_mode, rate_limit, tags)
    started_at = time.monotonic()

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        # linhas do -include-rr (request/response) podem passar de 64 KB
        limit=16 * 1024 * 1024,
    )

    findings: list[Finding] = []

    async def _read_stdout() -> None:
        # lê linha a linha: o que já foi encontrado fica guardado mesmo se estourar o tempo
        async for raw_line in process.stdout:
            finding = _parse_line(raw_line.decode(errors="replace"))
            if finding:
                findings.append(finding)
        await process.wait()

    stderr_task = asyncio.create_task(process.stderr.read())
    timed_out = False
    canceled = False

    # termina com o Nuclei, com o tempo limite ou com o cancelamento do usuário
    read_task = asyncio.create_task(_read_stdout())
    cancel_task = asyncio.create_task((cancel or asyncio.Event()).wait())
    done, _ = await asyncio.wait({read_task, cancel_task}, timeout=NUCLEI_TIMEOUT_SECONDS, return_when=asyncio.FIRST_COMPLETED)
    cancel_task.cancel()
    if read_task not in done:
        canceled = cancel is not None and cancel.is_set()
        timed_out = not canceled
        process.kill()
        await process.wait()
        read_task.cancel()
        try:
            await read_task
        except asyncio.CancelledError:
            pass

    stderr = await stderr_task
    duration = time.monotonic() - started_at

    if canceled:
        # o que já foi lido vale; nada de erro mesmo sem achados
        duration = time.monotonic() - started_at
        return findings, duration, ["Varredura cancelada pelo usuário: o resultado mostra só o que foi verificado até o cancelamento."]

    if timed_out:
        if not findings:
            raise NucleiExecutionError(
                f"O Nuclei excedeu o tempo limite de {NUCLEI_TIMEOUT_SECONDS}s e foi interrompido."
            )
        # varredura incompleta, mas com achados: devolve o que deu tempo de achar
        print(
            f"[nuclei] tempo limite de {NUCLEI_TIMEOUT_SECONDS}s atingido; "
            f"devolvendo {len(findings)} achado(s) parcial(is)."
        )
    elif process.returncode != 0 and not findings:
        raise NucleiExecutionError(stderr.decode(errors="replace") or "Falha ao executar o Nuclei.")

    warning = unreachable_warning(stderr.decode(errors="replace"), target_url)
    return findings, duration, [warning] if warning else []

TEMPLATE_UPDATE_TIMEOUT_SECONDS = int(os.getenv("NUCLEI_TEMPLATE_UPDATE_TIMEOUT_SECONDS", "600"))


def update_templates() -> None:
    """RF-45: baixa a versão mais recente dos templates do Nuclei."""
    if not NUCLEI_BINARY:
        raise NucleiNotInstalledError("Binário 'nuclei' não encontrado no PATH.")
    import subprocess

    try:
        subprocess.run(
            [NUCLEI_BINARY, "-update-templates"],
            check=True,
            capture_output=True,
            timeout=TEMPLATE_UPDATE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as err:
        raise NucleiExecutionError("A atualização dos templates demorou demais e foi interrompida.") from err
    except subprocess.CalledProcessError as err:
        # o detalhe (stderr) fica no log do motor; quem chama recebe uma mensagem curta
        print(f"[nuclei] falha ao atualizar templates: {err.stderr[-500:] if err.stderr else err}")
        raise NucleiExecutionError("O Nuclei não conseguiu atualizar os templates (sem internet?).") from err