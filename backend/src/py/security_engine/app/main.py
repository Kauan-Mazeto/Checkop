from fastapi import FastAPI, HTTPException

from .nuclei_runner import (
    NucleiExecutionError,
    NucleiNotInstalledError,
    run_nuclei_scan,
    update_templates,
)
from .schemas import NucleiScanRequest, NucleiScanResponse

app = FastAPI(title="Checkop Security Engine", version="1.0.0")


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
        )
    except NucleiNotInstalledError as err:
        raise HTTPException(status_code=503, detail=str(err))
    except NucleiExecutionError as err:
        raise HTTPException(status_code=502, detail=str(err))

    return NucleiScanResponse(
        findings=findings,
        templatesUsed=len(findings),
        durationSeconds=round(duration, 2),
    )


@app.post("/templates/update")
def update_nuclei_templates():
    try:
        update_templates()
    except NucleiNotInstalledError as err:
        raise HTTPException(status_code=503, detail=str(err))
    return {
        "message": "Templates do Nuclei atualizados com sucesso."
        }