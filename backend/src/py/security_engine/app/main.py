from fastapi import FastAPI, HTTPException
from .nuclei_runner import (NucleiExecutionError, NucleiNotInstalledError, run_nuclei_scan, update_templates)
from .schemas import NucleiScanRequest, NucleiScanResponse
from .zap_runner import ZapExecutionError, ZapNotAvailableError, run_zap_scan
from .schemas import ZapScanRequest, ZapScanResponse
from .subfinder_runner import SubfinderExecutionError, SubfinderNotInstalledError, run_subdomain_enum
from .schemas import SubdomainEnumRequest, SubdomainEnumResponse

app = FastAPI(title="Checkop", version="1.0.0")

# RNF-11:
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scans/nuclei", response_model=NucleiScanResponse)
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

    return NucleiScanResponse(findings=findings, templatesUsed=len(findings), durationSeconds=round(duration, 2))


@app.post("/scans/zap", response_model=ZapScanResponse)
async def scan_with_zap(payload: ZapScanRequest):
    try:
        findings, duration = await run_zap_scan(
            target_url=payload.targetUrl,
            safe_mode=payload.safeMode,
            scanner_ids=payload.scannerIds,
        )
    except ZapNotAvailableError as err:
        raise HTTPException(status_code=503, detail=str(err))
    except ZapExecutionError as err:
        raise HTTPException(status_code=502, detail=str(err))

    return ZapScanResponse(findings=findings, alertsFound=len(findings), durationSeconds=round(duration, 2))


@app.post("/templates/update")
def update_nuclei_templates():
    try:
        update_templates()
    except NucleiNotInstalledError as err:
        raise HTTPException(status_code=503, detail=str(err))
    return {
        "message": "Templates do Nuclei atualizados com sucesso."
        }

@app.post("/scans/zap", response_model=ZapScanResponse)
async def scan_with_zap(payload: ZapScanRequest):
    try:
        findings, duration = await run_zap_scan(
            target_url=payload.targetUrl,
            safe_mode=payload.safeMode,
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

@app.post("/scans/subdomains", response_model=SubdomainEnumResponse)
async def scan_subdomains(payload: SubdomainEnumRequest):
    try:
        findings, duration = await run_subdomain_enum(payload.domain)
    except SubfinderNotInstalledError as err:
        raise HTTPException(status_code=503, detail=str(err))
    except SubfinderExecutionError as err:
        raise HTTPException(status_code=502, detail=str(err))

    return SubdomainEnumResponse(findings=findings, subdomainsFound=len(findings), durationSeconds=round(duration, 2))