from pydantic import BaseModel, Field


class Finding(BaseModel):
    title: str
    description: str | None = None
    # severity segue o enum FindingSeverity do Prisma: INFO, LOW, MEDIUM, HIGH, CRITICAL
    severity: str
    # tool segue o enum ToolType do Prisma: ZAP, NUCLEI, SUBFINDER
    tool: str = "NUCLEI"
    affectedUrl: str | None = None
    cveId: str | None = None
    cvssScore: float | None = None
    rawRequest: str | None = None
    rawResponse: str | None = None
    remediation: str | None = None
    owaspUrl: str | None = None


# ---------- Nuclei (RF-10) ----------
class NucleiScanRequest(BaseModel):
    targetUrl: str
    safeMode: bool = True
    # limite de requisições/seg contra o alvo (RF-51)
    rateLimit: int = Field(default=10, ge=1, le=100)
    tags: list[str] | None = None


class NucleiScanResponse(BaseModel):
    findings: list[Finding]
    findingsCount: int
    durationSeconds: float


# ---------- ZAP (RF-09) ----------
class ZapScanRequest(BaseModel):
    targetUrl: str
    safeMode: bool = True
    scannerIds: list[str] | None = None


class ZapScanResponse(BaseModel):
    findings: list[Finding]
    alertsFound: int
    durationSeconds: float


# ---------- Subfinder ----------
class SubdomainEnumRequest(BaseModel):
    domain: str


class SubdomainEnumResponse(BaseModel):
    findings: list[Finding]
    subdomainsFound: int
    durationSeconds: float