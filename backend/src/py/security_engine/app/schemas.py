from pydantic import BaseModel, Field


class NucleiScanRequest(BaseModel):
    targetUrl: str
    safeMode: bool = True
    # limite de requisições/seg contra o alvo (RF-51 / RNF-15 aplicado ao motor)
    rateLimit: int = Field(default=10, ge=1, le=100)


class Finding(BaseModel):
    title: str
    description: str | None = None
    # severity baseado no prisma - Luidi #21/09/26
    severity: str
    tool: str = "NUCLEI"
    affectedUrl: str | None = None
    cveId: str | None = None
    cvssScore: float | None = None
    rawRequest: str | None = None
    rawResponse: str | None = None
    remediation: str | None = None
    owaspUrl: str | None = None


class NucleiScanResponse(BaseModel):
    findings: list[Finding]
    templatesUsed: int
    durationSeconds: float

class NucleiScanRequest(BaseModel):
    targetUrl: str
    safeMode: bool = True
    rateLimit: int = Field(default=10, ge=1, le=100)
    tags: list[str] | None = None


class ZapScanRequest(BaseModel):
    targetUrl: str
    safeMode: bool = True
    scannerIds: list[str] | None = None

class SubdomainEnumRequest(BaseModel):
    domain: str

class SubdomainEnumResponse(BaseModel):
    findings: list[Finding]
    subdomainsFound: int
    durationSeconds: float