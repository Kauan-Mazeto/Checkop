import hmac
import os

from fastapi import Depends, FastAPI, Header, HTTPException

from .nuclei_runner import (NucleiExecutionError, NucleiNotInstalledError, run_nuclei_scan, update_templates)
from .schemas import (NucleiScanRequest, NucleiScanResponse, ZapScanRequest, ZapScanResponse, SubdomainEnumRequest, SubdomainEnumResponse, SastScanRequest)
from .subfinder_runner import (SubfinderExecutionError, SubfinderNotInstalledError, run_subdomain_enum)
from .zap_runner import ZapExecutionError, ZapNotAvailableError, run_zap_scan
from .sast_runner import run_sast_scan, SastExecutionError

# B4: o motor dispara varreduras contra qualquer URL recebida, então só a API Node
# (que já validou usuário, alvo e autorização) pode chamá-lo. Sem token configurado
# o motor nem sobe: falhar fechado é melhor que ficar aberto por esquecimento.
ENGINE_TOKEN = os.getenv("ENGINE_TOKEN", "")
if not ENGINE_TOKEN:
    raise RuntimeError("Variável de ambiente ENGINE_TOKEN não definida; o motor não pode subir sem ela.")


def require_engine_token(x_engine_token: str = Header(default="")) -> None:
    if not hmac.compare_digest(x_engine_token.encode(), ENGINE_TOKEN.encode()):
        raise HTTPException(status_code=401, detail="Não autorizado.")


app = FastAPI(title="Checkop", version="1.0.0")
protected = [Depends(require_engine_token)]

# RNF-11
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scans/nuclei", response_model=NucleiScanResponse, dependencies=protected)
async def scan_with_nuclei(payload: NucleiScanRequest):
    try:
        findings, duration = await run_nuclei_scan(
            target_url=payload.targetUrl,
            safe_mode=payload.safeMode,
            rate_limit=payload.rateLimit,
            tags=payload.tags,
    )
        
    except NucleiNotInstalledError as err:
        raise HTTPException(status_code=503, detail=str(err))
    except NucleiExecutionError as err:
        raise HTTPException(status_code=502, detail=str(err))

    return NucleiScanResponse(
        findings=findings,
        findingsCount=len(findings),
        durationSeconds=round(duration, 2),
    )


@app.post("/scans/zap", response_model=ZapScanResponse, dependencies=protected)
async def scan_with_zap(payload: ZapScanRequest):
    try:
        findings, duration = await run_zap_scan(
            target_url=payload.targetUrl,
            safe_mode=payload.safeMode,
            scanner_ids=payload.scannerIds,
            auth=payload.auth,
            use_ajax_spider=payload.useAjaxSpider,
        )
    except ZapNotAvailableError as err:
        raise HTTPException(status_code=503, detail=str(err))
    except ZapExecutionError as err:
        raise HTTPException(status_code=502, detail=str(err))

    return ZapScanResponse(
        findings=findings,
        alertsFound=len(findings),
        durationSeconds=round(duration, 2),
    )


@app.post("/scans/subdomains", response_model=SubdomainEnumResponse, dependencies=protected)
async def scan_subdomains(payload: SubdomainEnumRequest):
    try:
        findings, duration = await run_subdomain_enum(payload.domain)
    except SubfinderNotInstalledError as err:
        raise HTTPException(status_code=503, detail=str(err))
    except SubfinderExecutionError as err:
        raise HTTPException(status_code=502, detail=str(err))

    return SubdomainEnumResponse(
        findings=findings,
        subdomainsFound=len(findings),
        durationSeconds=round(duration, 2),
    )

@app.post("/scans/sast", dependencies=protected)
async def scan_with_sast(payload: SastScanRequest):
    try:
        findings, duration = await run_sast_scan(payload.files)
    except SastExecutionError as e:
        raise HTTPException(status_code=502, detail=str(e))

    return {
        "findings": findings,
        "findingsCount": len(findings),
        "durationSeconds": round(duration, 2),
    }


# RF-45
@app.post("/templates/update", dependencies=protected)
def update_nuclei_templates():
    try:
        update_templates()
    except NucleiNotInstalledError as err:
        raise HTTPException(status_code=503, detail=str(err))
    return {"message": "Templates do Nuclei atualizados com sucesso."}