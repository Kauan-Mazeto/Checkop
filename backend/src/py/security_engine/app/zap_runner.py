import asyncio
import os
import re
import time
import uuid
from urllib.parse import quote

import httpx

from .cvss import CONFIDENCE_MAP, score_finding
from .mapping import map_to_owasp_category
from .schemas import Finding, ZapAuthConfig

ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

RISK_TO_SEVERITY = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}

POLL_INTERVAL_SECONDS = 2

# RF-51: ataque ativo contra alvo de produção não pode derrubar o site do usuário.
# Poucas threads por host e pausa entre requisições; em ambiente local, padrão do ZAP.
PRODUCTION_THREADS_PER_HOST = int(os.getenv("ZAP_PROD_THREADS_PER_HOST", "2"))
PRODUCTION_DELAY_MS = int(os.getenv("ZAP_PROD_DELAY_MS", "250"))
DEFAULT_THREADS_PER_HOST = int(os.getenv("ZAP_THREADS_PER_HOST", "4"))

# Limite de tempo por fase. Se estourar, o ZAP é parado e seguimos com o que já
# foi encontrado (resultado parcial) em vez de perder a varredura inteira.
# Dá para ajustar por variável de ambiente. Soma dos padrões = 27 min, abaixo do
# timeout de 30 min do cliente Node (security_engine_client.js).
SPIDER_MAX_SECONDS = int(os.getenv("ZAP_SPIDER_MAX_SECONDS", "300"))
PASSIVE_MAX_SECONDS = int(os.getenv("ZAP_PASSIVE_MAX_SECONDS", "120"))
ACTIVE_MAX_SECONDS = int(os.getenv("ZAP_ACTIVE_MAX_SECONDS", "1200"))
AJAX_SPIDER_MAX_SECONDS = int(os.getenv("ZAP_AJAX_SPIDER_MAX_SECONDS", "180"))
# navegadores em paralelo e espera após cada clique/recarga (padrão do ZAP: 1 e 1000 ms)
AJAX_SPIDER_BROWSERS = int(os.getenv("ZAP_AJAX_SPIDER_BROWSERS", "3"))
AJAX_SPIDER_EVENT_WAIT_MS = int(os.getenv("ZAP_AJAX_SPIDER_EVENT_WAIT_MS", "500"))
# espera o navegador subir (até ~15 s) antes de acompanhar o fim do AJAX Spider
AJAX_SPIDER_START_POLLS = 30
AJAX_SPIDER_START_POLL_SECONDS = 0.5
# Navegador do AJAX Spider. O Edge já vem no Windows (o ZAP baixa o driver sozinho);
# fora dele, Firefox. Valores aceitos pelo ZAP: edge-headless, chrome-headless, firefox-headless...
AJAX_SPIDER_BROWSER = os.getenv("ZAP_AJAX_SPIDER_BROWSER") or ("edge-headless" if os.name == "nt" else "firefox-headless")


class ZapNotAvailableError(Exception):
    pass


class ZapExecutionError(Exception):
    pass


# deleteAlerts do ZAP 2.17 apaga em lotes: repete até o alvo ficar sem alertas
CLEAR_ALERTS_MAX_ROUNDS = 10


async def _clear_target_alerts(client: httpx.AsyncClient, target_url: str) -> list[str]:
    """Apaga os alertas antigos DESTE alvo antes de varrer (os de outros alvos ficam).

    Sem isso, /core/view/alerts devolvia também os alertas das varreduras anteriores
    do mesmo alvo: falha já corrigida voltava como "persistente". Não usa newSession
    porque ela apagaria também a varredura em andamento de outro usuário.
    """
    try:
        for _ in range(CLEAR_ALERTS_MAX_ROUNDS):
            data = await _get(client, "/JSON/core/view/numberOfAlerts/", {"baseurl": target_url})
            if int(data.get("numberOfAlerts", 0)) == 0:
                return []
            await _get(client, "/JSON/alert/action/deleteAlerts/", {"baseurl": target_url})
    except ZapExecutionError as err:
        return [f"Não foi possível limpar os alertas antigos do ZAP ({err}); alertas de varreduras anteriores podem aparecer."]
    return ["Não foi possível limpar todos os alertas antigos do ZAP; alertas de varreduras anteriores podem aparecer."]


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
    client: httpx.AsyncClient, status_path: str, params: dict, max_seconds: float,
    cancel: asyncio.Event | None = None,
) -> bool:
    """Espera o ZAP chegar a 100%. False se estourou o tempo ou foi cancelado (quem chama para o scan)."""
    elapsed = 0.0
    while elapsed < max_seconds:
        if cancel is not None and cancel.is_set():
            return False
        data = await _get(client, status_path, params)
        if int(data.get("status", 0)) >= 100:
            return True
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        elapsed += POLL_INTERVAL_SECONDS
    return False


RISK_NAME_TO_CODE = {"informational": "0", "low": "1", "medium": "2", "high": "3"}


def _risk_code(alert: dict) -> str:
    # /JSON/core/view/alerts devolve só "risk" por extenso ("High"); "riskcode"
    # existe apenas nos relatórios exportados. Aceita os dois formatos.
    if alert.get("riskcode") is not None:
        return str(alert["riskcode"])
    return RISK_NAME_TO_CODE.get(str(alert.get("risk", "")).strip().lower(), "0")


def is_false_positive(alert: dict) -> bool:
    # o próprio ZAP marca alguns alertas como falso positivo: não viram achado
    return str(alert.get("confidence", "")).strip().lower() in ("false positive", "0")


# ---------- prova de conceito (PoC) ----------
# A busca de alertas do ZAP só traz o trecho que provou a falha ("evidence",
# ex.: "HTTP/1.1 500 Internal Server Error"). A requisição e a resposta completas
# vêm da mensagem HTTP do alerta (messageId), buscada à parte.
POC_MESSAGES_MAX = int(os.getenv("ZAP_POC_MESSAGES_MAX", "300"))
POC_BODY_WINDOW = 800      # caracteres de cada lado da evidência no corpo da resposta
POC_BODY_HEAD = 2000       # sem a evidência no corpo: o começo dele
POC_REQUEST_BODY_MAX = 4000


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else f"{text[:limit]}\n[... {len(text) - limit} caracteres omitidos]"


def _response_excerpt(body: str, evidence: str | None) -> str:
    """Trecho do corpo em volta da evidência, marcada com >>> <<<."""
    if not body:
        return ""
    at = body.find(evidence) if evidence else -1
    if at < 0:
        return _clip(body, POC_BODY_HEAD)
    start, end = max(0, at - POC_BODY_WINDOW), min(len(body), at + len(evidence) + POC_BODY_WINDOW)
    excerpt = body[start:at] + ">>> " + evidence + " <<<" + body[at + len(evidence):end]
    return ("[...]\n" if start > 0 else "") + excerpt + ("\n[...]" if end < len(body) else "")


def _curl_command(request_header: str, request_body: str) -> str | None:
    """Comando curl equivalente à requisição do ataque.

    Cookies e Authorization ficam de fora: são a sessão de quem rodou a varredura
    (varredura autenticada) e não podem ir parar num relatório exportado."""
    lines = [line for line in request_header.replace("\r\n", "\n").split("\n") if line.strip()]
    if not lines:
        return None
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    method, url = parts[0], parts[1]
    quote_dq = lambda value: value.replace("\\", "\\\\").replace('"', '\\"')
    command = ["curl -i"]
    if method.upper() != "GET":
        command.append(f"-X {method}")
    command.append(f'"{quote_dq(url)}"')
    for line in lines[1:]:
        name = line.split(":", 1)[0].strip().lower()
        if name == "content-type":
            command.append(f'-H "{quote_dq(line.strip())}"')
    if request_body:
        command.append(f'--data-raw "{quote_dq(request_body[:POC_REQUEST_BODY_MAX])}"')
    return " ".join(command)


async def _attach_messages(client: httpx.AsyncClient, alerts: list[dict]) -> None:
    """Busca, em paralelo, a mensagem HTTP de cada alerta (melhor esforço)."""
    semaphore = asyncio.Semaphore(8)

    async def one(alert: dict) -> None:
        message_id = alert.get("messageId")
        if not message_id:
            return
        async with semaphore:
            try:
                data = await _get(client, "/JSON/core/view/message/", {"id": str(message_id)})
            except (ZapExecutionError, ZapNotAvailableError):
                return
        alert["_message"] = data.get("message") or {}

    await asyncio.gather(*(one(alert) for alert in alerts[:POC_MESSAGES_MAX]))


_SESSION_HEADERS = re.compile(r"^(cookie|authorization|proxy-authorization|x-api-key|x-auth-token)\s*:.*$", re.IGNORECASE | re.MULTILINE)


def _redact_session(request_header: str) -> str:
    """Oculta o valor dos cabeçalhos de sessão: a PoC vai para relatórios exportáveis."""
    return _SESSION_HEADERS.sub(lambda m: f"{m.group(1)}: [omitido no relatório]", request_header)


def _poc_fields(alert: dict) -> dict:
    """rawRequest / rawResponse / reproduction a partir da mensagem do alerta."""
    evidence = alert.get("evidence") or None
    message = alert.get("_message") or {}
    request_header = message.get("requestHeader") or ""
    request_body = message.get("requestBody") or ""
    response_header = message.get("responseHeader") or ""
    response_body = message.get("responseBody") or ""

    if not request_header and not response_header:
        # sem a mensagem: fica só o trecho da evidência, como antes
        return {"rawRequest": alert.get("request"), "rawResponse": evidence, "reproduction": None}

    request = _redact_session(request_header).rstrip()
    if request_body:
        request += "\n\n" + _clip(request_body, POC_REQUEST_BODY_MAX)
    response = response_header.rstrip()
    excerpt = _response_excerpt(response_body, evidence)
    if excerpt:
        response += "\n\n" + excerpt
    elif evidence and evidence not in response:
        response += f"\n\nEvidência: {evidence}"
    return {"rawRequest": request, "rawResponse": response, "reproduction": _curl_command(request_header, request_body)}


def _parse_alert(alert: dict) -> Finding:
    risk_code = _risk_code(alert)
    tool_severity = RISK_TO_SEVERITY.get(risk_code, "INFO")

    cwe_id = alert.get("cweid")
    tags = [f"cwe-{cwe_id}"] if cwe_id and cwe_id != "-1" else []
    # nota CVSS 3.1 calculada pelo vetor padrão da classe (CWE) da falha
    cvss = score_finding(tool_severity, None, [str(cwe_id)] if tags else [])

    return Finding(
        title=alert.get("name") or "Achado do ZAP",
        description=alert.get("description"),
        severity=cvss["severity"],
        tool="ZAP",
        ruleId=str(alert["pluginId"]) if alert.get("pluginId") is not None else None,
        affectedUrl=alert.get("url"),
        cveId=None,
        cvssScore=cvss["cvssScore"],
        cvssVector=cvss["cvssVector"],
        cvssSource=cvss["cvssSource"],
        confidence=CONFIDENCE_MAP.get(str(alert.get("confidence", "")).strip().lower()),
        parameter=alert.get("param") or None,
        attack=alert.get("attack") or None,
        **_poc_fields(alert),
        remediation=alert.get("solution"),
        owaspUrl=map_to_owasp_category(tags) if tags else None,
    )


# Regras beta (CSRF ativo, SSRF, CORS ativo, backup/.git, Advanced SQLi) não vêm no
# ZAP por padrão; são instaladas uma vez pelo Marketplace via API.
BETA_ADDONS = ("ascanrulesBeta", "pscanrulesBeta")
_beta_addons_ready = False


async def ensure_beta_addons(client: httpx.AsyncClient) -> list[str]:
    """Instala as regras beta se faltarem. Devolve avisos; nunca derruba a varredura."""
    global _beta_addons_ready
    if _beta_addons_ready:
        return []
    try:
        data = await _get(client, "/JSON/autoupdate/view/installedAddons/", {})
        installed = {addon.get("id") for addon in data.get("installedAddons", [])}
        for addon_id in BETA_ADDONS:
            if addon_id not in installed:
                await _get(client, "/JSON/autoupdate/action/installAddon/", {"id": addon_id})
        _beta_addons_ready = True
        return []
    except ZapExecutionError as err:
        return [f"Não foi possível instalar as regras beta do ZAP ({err}); algumas verificações ficam de fora."]


async def _set_active_scanners(client: httpx.AsyncClient, scanner_ids: list[str] | None) -> list[str]:
    """Seleciona os scanners ativos e devolve os ids que o ZAP não reconheceu.

    A seleção é global no ZAP: por isso a varredura completa (None) reativa tudo,
    senão herdaria a seleção restrita da varredura anterior.
    """
    if scanner_ids is None:
        await _get(client, "/JSON/ascan/action/enableAllScanners/", {})
        return []

    await _get(client, "/JSON/ascan/action/disableAllScanners/", {})
    try:
        await _get(client, "/JSON/ascan/action/enableScanners/", {"ids": ",".join(scanner_ids)})
        return []
    except ZapExecutionError:
        # algum id não existe nesta instalação: habilita um a um e segue com os demais
        missing = []
        for scanner_id in scanner_ids:
            try:
                await _get(client, "/JSON/ascan/action/enableScanners/", {"ids": scanner_id})
            except ZapExecutionError:
                missing.append(scanner_id)
        return missing

def _enc(value: str) -> str:
    return quote(value, safe="")


async def _setup_authentication(
    client: httpx.AsyncClient, target_url: str, auth: ZapAuthConfig, context_name: str
) -> None:
    ctx_data = await _get(client, "/JSON/context/action/newContext/", {"contextName": context_name})
    context_id = ctx_data.get("contextId")
    if context_id is None:
        raise ZapExecutionError(f"Não foi possível criar o contexto do ZAP: {ctx_data}")

    # regex: URL do alvo escapada + qualquer coisa depois
    include_regex = re.escape(target_url.rstrip("/")) + ".*"
    await _get(client, "/JSON/context/action/includeInContext/", {
        "contextName": context_name,
        "regex": include_regex,
    })

    # O ZAP lê esses parâmetros em dois níveis, então o valor aninhado
    # (loginRequestData) e a URL precisam ir URL-encoded dentro do config.
    login_request_data = f"{auth.usernameField}={{%username%}}&{auth.passwordField}={{%password%}}"
    auth_config = f"loginUrl={_enc(auth.loginUrl)}&loginRequestData={_enc(login_request_data)}"
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

    # usuário e senha também vão codificados (senha com & ou = não pode quebrar o parse)
    await _get(client, "/JSON/users/action/setAuthenticationCredentials/", {
        "contextId": context_id,
        "userId": user_id,
        "authCredentialsConfigParams": f"username={_enc(auth.username)}&password={_enc(auth.password)}",
    })
    await _get(client, "/JSON/users/action/setUserEnabled/", {
        "contextId": context_id,
        "userId": user_id,
        "enabled": "true",
    })

    # Limitação: o modo "forced user" é global na instância do ZAP. Enquanto um scan
    # autenticado roda, qualquer outro scan no mesmo ZAP também sai como esse usuário.
    await _get(client, "/JSON/forcedUser/action/setForcedUser/", {
        "contextId": context_id,
        "userId": user_id,
    })
    await _get(client, "/JSON/forcedUser/action/setForcedUserModeEnabled/", {"boolean": "true"})


async def _cleanup_authentication(client: httpx.AsyncClient, context_name: str) -> None:
    # melhor esforço: roda sempre (sucesso ou erro) para não vazar sessão/contexto
    # para os próximos scans na mesma instância do ZAP.
    for path, params in (
        ("/JSON/forcedUser/action/setForcedUserModeEnabled/", {"boolean": "false"}),
        ("/JSON/context/action/removeContext/", {"contextName": context_name}),
    ):
        try:
            await _get(client, path, params)
        except (ZapNotAvailableError, ZapExecutionError):
            pass

async def _run_ajax_spider(
    client: httpx.AsyncClient, target_url: str, max_seconds: float, context_name: str | None,
    cancel: asyncio.Event | None = None,
) -> None:
    # subtreeOnly mantém o spider restrito ao alvo, sem depender de escopo/contexto.
    params = {"url": target_url, "subtreeOnly": "true"}
    # o ZAP roda um AJAX Spider por vez: se sobrou um rodando, encerra antes
    # (senão a configuração e o início voltam "scan_in_progress")
    status = await _get(client, "/JSON/ajaxSpider/view/status/", {})
    if status.get("status") == "running":
        await _get(client, "/JSON/ajaxSpider/action/stop/", {})
        for _ in range(15):
            await asyncio.sleep(POLL_INTERVAL_SECONDS)
            status = await _get(client, "/JSON/ajaxSpider/view/status/", {})
            if status.get("status") != "running":
                break
    await _tune_ajax_spider(client)
    if context_name:
        params["contextName"] = context_name
    started = await _get(client, "/JSON/ajaxSpider/action/scan/", params)
    if started.get("Result") not in ("OK", None):
        raise ZapExecutionError(f"O ZAP não iniciou o Spider AJAX: {started}")

    # o status só vira "running" depois que o navegador sobe: sem esperar por isso,
    # o primeiro "stopped" era lido como "terminou", o motor seguia com 0 páginas e
    # o scan ativo rodava junto com o AJAX
    for _ in range(AJAX_SPIDER_START_POLLS):
        status = await _get(client, "/JSON/ajaxSpider/view/status/", {})
        if status.get("status") == "running":
            break
        await asyncio.sleep(AJAX_SPIDER_START_POLL_SECONDS)

    elapsed = 0.0
    while elapsed < max_seconds:
        if cancel is not None and cancel.is_set():
            break
        status = await _get(client, "/JSON/ajaxSpider/view/status/", {})
        if status.get("status") == "stopped":
            return
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        elapsed += POLL_INTERVAL_SECONDS

    await _get(client, "/JSON/ajaxSpider/action/stop/", {})


# marcas de app de página única no HTML inicial (Angular, React, Vue, Next, Nuxt, Svelte...)
_SPA_MARKERS = re.compile(
    r"<app-root|ng-version=|\bid=[\"'](root|app|__next|__nuxt|svelte)[\"']|data-reactroot|__NEXT_DATA__|window\.__NUXT__",
    re.IGNORECASE,
)
_SCRIPT_BLOCKS = re.compile(r"<(script|style)\b.*?</\1>", re.IGNORECASE | re.DOTALL)
_TAGS = re.compile(r"<[^>]+>")
SPA_MIN_VISIBLE_TEXT = 200  # menos que isso de texto visível + JS = tela montada no navegador
SPA_MAX_PAGES = 2  # o spider normal achou só a raiz (e talvez mais uma)


def detect_spa(html: str, pages_found: int) -> str | None:
    """Diz por que a página parece SPA (precisa do AJAX Spider) ou None."""
    if not html:
        return None
    if _SPA_MARKERS.search(html):
        return "o HTML tem a raiz de um framework JavaScript"
    has_scripts = re.search(r"<script\b", html, re.IGNORECASE) is not None
    visible = re.sub(r"\s+", " ", _TAGS.sub(" ", _SCRIPT_BLOCKS.sub(" ", html))).strip()
    if has_scripts and len(visible) < SPA_MIN_VISIBLE_TEXT:
        return "a página é quase toda montada por JavaScript"
    if has_scripts and pages_found <= SPA_MAX_PAGES:
        return "o spider tradicional quase não achou links"
    return None


async def _initial_html(client: httpx.AsyncClient, target_url: str) -> str:
    # reaproveita a resposta que o accessUrl já trouxe: nada de requisição extra ao alvo
    data = await _get(client, "/JSON/core/view/messages/", {"baseurl": target_url, "start": "0", "count": "10"})
    for message in data.get("messages", []):
        if "text/html" in message.get("responseHeader", "").lower() and message.get("responseBody"):
            return message["responseBody"]
    return ""


async def _spider_pages(client: httpx.AsyncClient, spider_id: str) -> int:
    data = await _get(client, "/JSON/spider/view/results/", {"scanId": spider_id})
    return len(data.get("results", []))


async def _tune_ajax_spider(client: httpx.AsyncClient) -> None:
    # opções globais do ZAP; cada uma é melhor esforço (versões antigas podem não ter)
    options = (
        ("setOptionBrowserId", "String", AJAX_SPIDER_BROWSER),
        ("setOptionNumberOfBrowsers", "Integer", str(AJAX_SPIDER_BROWSERS)),
        ("setOptionMaxDuration", "Integer", str(max(1, AJAX_SPIDER_MAX_SECONDS // 60))),  # minutos
        ("setOptionClickElemsOnce", "Boolean", "true"),
        ("setOptionEventWait", "Integer", str(AJAX_SPIDER_EVENT_WAIT_MS)),
        ("setOptionReloadWait", "Integer", str(AJAX_SPIDER_EVENT_WAIT_MS)),
    )
    for action, kind, value in options:
        try:
            await _get(client, f"/JSON/ajaxSpider/action/{action}/", {kind: value})
        except ZapExecutionError:
            if action == "setOptionBrowserId":
                raise


def should_run_active_scan(safe_mode: bool, active_scan: bool | None) -> bool:
    # sem instrução explícita, mantém a regra antiga (RF-52): nada de ativo em produção
    return (not safe_mode) if active_scan is None else active_scan


async def _set_active_scan_throttling(client: httpx.AsyncClient, safe_mode: bool) -> None:
    # opções globais do ZAP: sempre redefinidas, senão uma varredura herda a da anterior
    threads = PRODUCTION_THREADS_PER_HOST if safe_mode else DEFAULT_THREADS_PER_HOST
    delay = PRODUCTION_DELAY_MS if safe_mode else 0
    await _get(client, "/JSON/ascan/action/setOptionThreadPerHost/", {"Integer": str(threads)})
    await _get(client, "/JSON/ascan/action/setOptionDelayInMs/", {"Integer": str(delay)})
    # a regra de DOM XSS abre um navegador (padrão: Firefox); usa o mesmo do AJAX Spider
    try:
        await _get(client, "/JSON/ruleConfig/action/setRuleConfigValue/", {"key": "rules.domxss.browserid", "value": AJAX_SPIDER_BROWSER})
    except ZapExecutionError:
        pass


async def run_zap_scan(
    target_url: str,
    safe_mode: bool,
    active_scan: bool | None = None,
    scanner_ids: list[str] | None = None,
    auth: ZapAuthConfig | None = None,
    use_ajax_spider: bool = False,
    cancel: asyncio.Event | None = None,
) -> tuple[list[Finding], float, list[str]]:
    started_at = time.monotonic()
    warnings: list[str] = []
    cancel = cancel or asyncio.Event()
    # nome único por varredura: o ZAP recusa criar dois contextos com o mesmo nome
    context_name = f"checkop-{uuid.uuid4().hex[:8]}" if auth is not None else None

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # o resultado traz só o que ESTA varredura encontrou neste alvo
            warnings += await _clear_target_alerts(client, target_url)
            warnings += await ensure_beta_addons(client)
            await _get(client, "/JSON/core/action/accessUrl/", {"url": target_url})

            if auth is not None:
                await _setup_authentication(client, target_url, auth, context_name)

            # 1) spider: mapeia a superfície de ataque (RF-33).
            # O tradicional roda sempre: segue links e formulários do HTML.
            spider_data = await _get(client, "/JSON/spider/action/scan/", {"url": target_url, "recurse": "true"})
            spider_id = spider_data.get("scan")
            if spider_id is None:
                raise ZapExecutionError(f"O ZAP não iniciou o spider: {spider_data}")
            if not await _wait_until(client, "/JSON/spider/view/status/", {"scanId": spider_id}, SPIDER_MAX_SECONDS, cancel):
                await _get(client, "/JSON/spider/action/stop/", {"scanId": spider_id})

            # SPA (Angular/React/Vue): o AJAX spider complementa, abrindo a página num
            # navegador headless. É lento (minutos), então só roda quando o usuário
            # força a opção ou quando a página parece SPA. Sem navegador ele termina
            # "vazio" sem erro, e isso vira aviso em vez de uma varredura que parece limpa.
            if not use_ajax_spider and not cancel.is_set():
                try:
                    spa_reason = detect_spa(await _initial_html(client, target_url), await _spider_pages(client, spider_id))
                except ZapExecutionError:
                    spa_reason = None
                if spa_reason:
                    use_ajax_spider = True
                    warnings.append(f"Site identificado como SPA ({spa_reason}): o AJAX Spider foi acionado para mapear as telas.")
            if use_ajax_spider and not cancel.is_set():
                try:
                    await _run_ajax_spider(client, target_url, AJAX_SPIDER_MAX_SECONDS, context_name, cancel)
                    found = await _get(client, "/JSON/ajaxSpider/view/numberOfResults/", {})
                    if int(found.get("numberOfResults", 0)) == 0:
                        warnings.append(
                            f"O AJAX Spider não encontrou páginas (navegador {AJAX_SPIDER_BROWSER} indisponível?). "
                            "A varredura usou só o spider tradicional."
                        )
                except ZapExecutionError as exc:
                    warnings.append(f"O AJAX Spider falhou e a varredura usou só o spider tradicional: {exc}")

            # 2) varredura passiva: espera a fila de análise esvaziar
            elapsed = 0.0
            while elapsed < PASSIVE_MAX_SECONDS and not cancel.is_set():
                pscan_data = await _get(client, "/JSON/pscan/view/recordsToScan/", {})
                if int(pscan_data.get("recordsToScan", 0)) == 0:
                    break
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
                elapsed += POLL_INTERVAL_SECONDS

            # 3) varredura ativa: fora de produção, ou em produção verificada com
            # opt-in explícito (o Node só manda activeScan=True nesses casos)
            # scanner_ids == [] -> objetivo só passivo: nenhum ataque é enviado
            if should_run_active_scan(safe_mode, active_scan) and scanner_ids != [] and not cancel.is_set():
                await _set_active_scan_throttling(client, safe_mode)
                missing = await _set_active_scanners(client, scanner_ids)
                if missing:
                    warnings.append(f"Regras do ZAP indisponíveis nesta instalação: {', '.join(missing)}.")
                ascan_data = await _get(client, "/JSON/ascan/action/scan/", {"url": target_url, "recurse": "true"})
                ascan_id = ascan_data.get("scan")
                if ascan_id is None:
                    raise ZapExecutionError(f"O ZAP não iniciou a varredura ativa: {ascan_data}")
                if not await _wait_until(client, "/JSON/ascan/view/status/", {"scanId": ascan_id}, ACTIVE_MAX_SECONDS, cancel):
                    await _get(client, "/JSON/ascan/action/stop/", {"scanId": ascan_id})

            alerts_data = await _get(client, "/JSON/core/view/alerts/", {"baseurl": target_url})
            # requisição e resposta completas de cada alerta, para a PoC
            await _attach_messages(client, [a for a in alerts_data.get("alerts", []) if not is_false_positive(a)])
        finally:
            if context_name is not None:
                await _cleanup_authentication(client, context_name)

    if cancel.is_set():
        warnings.append("Varredura cancelada pelo usuário: o resultado mostra só o que foi verificado até o cancelamento.")
    duration = time.monotonic() - started_at
    findings = [_parse_alert(a) for a in alerts_data.get("alerts", []) if not is_false_positive(a)]
    return findings, duration, warnings