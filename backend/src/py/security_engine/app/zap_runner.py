import asyncio
import os
import time
import asyncio
import os
import re
import time
import httpx

from .mapping import map_to_owasp_category, fallback_cvss_for_severity
from .schemas import Finding, ZapAuthConfig

ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

RISK_TO_SEVERITY = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}
RISK_TO_CVSS_FALLBACK = {"0": 0.0, "1": 3.0, "2": 5.5, "3": 8.5}

POLL_INTERVAL_SECONDS = 2
CONTEXT_NAME = "checkop-scan-context"

# Limite de tempo por fase. Se estourar, o ZAP é parado e seguimos com o que já
# foi encontrado (resultado parcial) em vez de perder a varredura inteira.
# Dá para ajustar por variável de ambiente. Soma dos padrões = 27 min, abaixo do
# timeout de 30 min do cliente Node (security_engine_client.js).
SPIDER_MAX_SECONDS = int(os.getenv("ZAP_SPIDER_MAX_SECONDS", "300"))
PASSIVE_MAX_SECONDS = int(os.getenv("ZAP_PASSIVE_MAX_SECONDS", "120"))
ACTIVE_MAX_SECONDS = int(os.getenv("ZAP_ACTIVE_MAX_SECONDS", "1200"))
AJAX_SPIDER_MAX_SECONDS = int(os.getenv("ZAP_AJAX_SPIDER_MAX_SECONDS", "300"))


class ZapNotAvailableError(Exception):
    pass


class ZapExecutionError(Exception):
    pass


def _params(extra: dict) -> dict:
    return {"apikey": ZAP_API_KEY, **extra}


async def _get(client: httpx.AsyncClient, path: str, params: dict) -> dict:
    try:
        resp = await client.get(f"{ZAP_API_URL}{path}", params=_params(params))
    except httpx.HTTPError as err:
        # não conseguiu falar com o ZAP (fora do ar, porta errada, timeout)
        raise ZapNotAvailableError(f"Motor OWASP ZAP indisponível: {err}") from err

    if resp.status_code >= 400:
        # o ZAP respondeu, mas recusou (ex.: api key errada, URL inválida)
        raise ZapExecutionError(f"ZAP recusou a requisição ({resp.status_code}): {resp.text[:200]}")

    try:
        return resp.json()
    except ValueError as err:
        raise ZapExecutionError("Resposta inesperada (não-JSON) do ZAP.") from err


async def _wait_until(
    client: httpx.AsyncClient, status_path: str, params: dict, max_seconds: float
) -> bool:
    """Espera o ZAP chegar a 100%. Retorna True se terminou, False se estourou o tempo."""
    elapsed = 0.0
    while elapsed < max_seconds:
        data = await _get(client, status_path, params)
        if int(data.get("status", 0)) >= 100:
            return True
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        elapsed += POLL_INTERVAL_SECONDS
    return False


def _parse_alert(alert: dict) -> Finding:
    risk_code = str(alert.get("riskcode", "0"))
    severity = RISK_TO_SEVERITY.get(risk_code, "INFO")
    cvss_score = RISK_TO_CVSS_FALLBACK.get(risk_code, fallback_cvss_for_severity(severity.lower()))

    cwe_id = alert.get("cweid")
    tags = [f"cwe-{cwe_id}"] if cwe_id and cwe_id != "-1" else []

    return Finding(
        title=alert.get("name") or "Achado do ZAP",
        description=alert.get("description"),
        severity=severity,
        tool="ZAP",
        affectedUrl=alert.get("url"),
        cveId=None,
        cvssScore=cvss_score,
        rawRequest=alert.get("request"),
        rawResponse=alert.get("evidence"),
        remediation=alert.get("solution"),
        owaspUrl=map_to_owasp_category(tags) if tags else None,
    )


async def _set_active_scanners(client: httpx.AsyncClient, scanner_ids: list[str] | None) -> None:
    if not scanner_ids:
        return
    await _get(client, "/JSON/ascan/action/disableAllScanners/", {})
    await _get(client, "/JSON/ascan/action/setEnabledScanners/", {"ids": ",".join(scanner_ids)})

async def _setup_authentication(client: httpx.AsyncClient, target_url: str, auth: ZapAuthConfig) -> str:
    ctx_data = await _get(client, "/JSON/context/action/newContext/", {"contextName": CONTEXT_NAME})
    context_id = ctx_data.get("contextId")
    if context_id is None:
        raise ZapExecutionError(f"Não foi possível criar o contexto do ZAP: {ctx_data}")

    include_regex = re.escape(target_url.rstrip("/")) + ".*"
    await _get(client, "/JSON/context/action/includeInContext/", {
        "contextName": CONTEXT_NAME,
        "regex": include_regex,
    })

    login_request_data = f"{auth.usernameField}={{%username%}}&{auth.passwordField}={{%password%}}"
    auth_config = (
        f"loginUrl={auth.loginUrl}&loginRequestData={login_request_data}"
    )
    await _get(client, "/JSON/authentication/action/setAuthenticationMethod/", {
        "contextId": context_id,
        "authMethodName": "formBasedAuthentication",
        "authMethodConfigParams": auth_config,
    })

    if auth.loggedInIndicator:
        await _get(client, "/JSON/authentication/action/setLoggedInIndicator/", {
            "contextId": context_id,
            "loggedInIndicatorRegex": auth.loggedInIndicator,
        })
    if auth.loggedOutIndicator:
        await _get(client, "/JSON/authentication/action/setLoggedOutIndicator/", {
            "contextId": context_id,
            "loggedOutIndicatorRegex": auth.loggedOutIndicator,
        })

    user_data = await _get(client, "/JSON/users/action/newUser/", {
        "contextId": context_id,
        "name": "checkop-scan-user",
    })
    user_id = user_data.get("userId")
    if user_id is None:
        raise ZapExecutionError(f"Não foi possível criar o usuário de teste no ZAP: {user_data}")

    await _get(client, "/JSON/users/action/setAuthenticationCredentials/", {
        "contextId": context_id,
        "userId": user_id,
        "authCredentialsConfigParams": f"username={auth.username}&password={auth.password}",
    })
    await _get(client, "/JSON/users/action/setUserEnabled/", {
        "contextId": context_id,
        "userId": user_id,
        "enabled": "true",
    })

    await _get(client, "/JSON/forcedUser/action/setForcedUser/", {
        "contextId": context_id,
        "userId": user_id,
    })
    await _get(client, "/JSON/forcedUser/action/setForcedUserModeEnabled/", {"boolean": "true"})

    return context_id


async def _run_ajax_spider(client: httpx.AsyncClient, target_url: str, max_seconds: float) -> None:
    started = await _get(client, "/JSON/ajaxSpider/action/scan/", {"url": target_url, "inScope": "true"})
    if started.get("Result") not in ("OK", None):
        raise ZapExecutionError(f"O ZAP não iniciou o Spider AJAX: {started}")

    elapsed = 0.0
    while elapsed < max_seconds:
        status = await _get(client, "/JSON/ajaxSpider/view/status/", {})
        if status.get("status") == "stopped":
            return
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        elapsed += POLL_INTERVAL_SECONDS

    await _get(client, "/JSON/ajaxSpider/action/stop/", {})

async def run_zap_scan(
    target_url: str,
    safe_mode: bool,
    scanner_ids: list[str] | None = None,
    auth: ZapAuthConfig | None = None,
    use_ajax_spider: bool = False,
) -> tuple[list[Finding], float]:
    started_at = time.monotonic()

    async with httpx.AsyncClient(timeout=30.0) as client:
        await _get(client, "/JSON/core/action/accessUrl/", {"url": target_url})

        if auth is not None:
            await _setup_authentication(client, target_url, auth)

        # 1) spider: mapeia a superfície de ataque (RF-33).
        # AJAX spider para SPAs (Angular/React); spider tradicional, senão.
        if use_ajax_spider:
            await _run_ajax_spider(client, target_url, AJAX_SPIDER_MAX_SECONDS)
        else:
            spider_data = await _get(client, "/JSON/spider/action/scan/", {"url": target_url, "recurse": "true"})
            spider_id = spider_data.get("scan")
            if spider_id is None:
                raise ZapExecutionError(f"O ZAP não iniciou o spider: {spider_data}")
            if not await _wait_until(client, "/JSON/spider/view/status/", {"scanId": spider_id}, SPIDER_MAX_SECONDS):
                await _get(client, "/JSON/spider/action/stop/", {"scanId": spider_id})

        # 2) varredura passiva: espera a fila de análise esvaziar
        elapsed = 0.0
        while elapsed < PASSIVE_MAX_SECONDS:
            pscan_data = await _get(client, "/JSON/pscan/view/recordsToScan/", {})
            if int(pscan_data.get("recordsToScan", 0)) == 0:
                break
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
            elapsed += POLL_INTERVAL_SECONDS

        # 3) varredura ativa: só fora de produção (RF-52)
        if not safe_mode:
            await _set_active_scanners(client, scanner_ids)
            ascan_data = await _get(client, "/JSON/ascan/action/scan/", {"url": target_url, "recurse": "true"})
            ascan_id = ascan_data.get("scan")
            if ascan_id is None:
                raise ZapExecutionError(f"O ZAP não iniciou a varredura ativa: {ascan_data}")
            if not await _wait_until(client, "/JSON/ascan/view/status/", {"scanId": ascan_id}, ACTIVE_MAX_SECONDS):
                await _get(client, "/JSON/ascan/action/stop/", {"scanId": ascan_id})

        alerts_data = await _get(client, "/JSON/core/view/alerts/", {"baseurl": target_url})

        if auth is not None:
            # desliga o modo forçado para não vazar pra scans futuros na mesma instância do ZAP
    await _get(client, "/JSON/forcedUser/action/setForcedUserModeEnabled/", {"boolean": "false"})

    duration = time.monotonic() - started_at
    findings = [_parse_alert(a) for a in alerts_data.get("alerts", [])]
    return findings, duration