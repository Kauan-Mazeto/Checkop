import asyncio
import time
import os

import httpx

from .mapping import map_to_owasp_category, fallback_cvss_for_severity
from .schemas import Finding

ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

RISK_TO_SEVERITY = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}
RISK_TO_CVSS_FALLBACK = {"0": 0.0, "1": 3.0, "2": 5.5, "3": 8.5}

POLL_INTERVAL_SECONDS = 2
MAX_POLL_SECONDS = 600


class ZapNotAvailableError(Exception):
    pass


class ZapExecutionError(Exception):
    pass


def _params(extra: dict) -> dict:
    return {"apikey": ZAP_API_KEY, **extra}


async def _get(client: httpx.AsyncClient, path: str, params: dict) -> dict:
    try:
        resp = await client.get(f"{ZAP_API_URL}{path}", params=_params(params))
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as err:
        raise ZapNotAvailableError(f"Motor OWASP ZAP indisponível: {err}") from err


async def _wait_until(client: httpx.AsyncClient, status_path: str, params: dict) -> None:
    elapsed = 0
    while elapsed < MAX_POLL_SECONDS:
        data = await _get(client, status_path, params)
        if int(data.get("status", 0)) >= 100:
            return
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        elapsed += POLL_INTERVAL_SECONDS
    raise ZapExecutionError("Tempo limite excedido aguardando o ZAP concluir a varredura.")


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


async def run_zap_scan(
    target_url: str, safe_mode: bool, scanner_ids: list[str] | None = None
) -> tuple[list[Finding], float]:
    started_at = time.monotonic()

    async with httpx.AsyncClient(timeout=30.0) as client:
        await _get(client, "/JSON/core/action/accessUrl/", {"url": target_url})

        spider_data = await _get(client, "/JSON/spider/action/scan/", {"url": target_url, "recurse": "true"})
        await _wait_until(client, "/JSON/spider/view/status/", {"scanId": spider_data.get("scan")})

        elapsed = 0
        while elapsed < MAX_POLL_SECONDS:
            pscan_data = await _get(client, "/JSON/pscan/view/recordsToScan/", {})
            if int(pscan_data.get("recordsToScan", 0)) == 0:
                break
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
            elapsed += POLL_INTERVAL_SECONDS

        if not safe_mode:
            await _set_active_scanners(client, scanner_ids)
            ascan_data = await _get(client, "/JSON/ascan/action/scan/", {"url": target_url, "recurse": "true"})
            await _wait_until(client, "/JSON/ascan/view/status/", {"scanId": ascan_data.get("scan")})

        alerts_data = await _get(client, "/JSON/core/view/alerts/", {"baseurl": target_url})

    duration = time.monotonic() - started_at
    findings = [_parse_alert(a) for a in alerts_data.get("alerts", [])]
    return findings, duration