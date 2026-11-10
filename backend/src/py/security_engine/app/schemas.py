from pydantic import BaseModel, Field


class Finding(BaseModel):
    title: str
    description: str | None = None
    severity: str
    tool: str = "NUCLEI"
    affectedUrl: str | None = None
    cveId: str | None = None
    cvssScore: float | None = None
    rawRequest: str | None = None
    rawResponse: str | None = None
    remediation: str | None = None
    owaspUrl: str | None = None

class ZapAuthConfig(BaseModel):
    loginUrl: str
    usernameField: str
    passwordField: str
    username: str
    password: str
    loggedInIndicator: str | None = None
    loggedOutIndicator: str | None = None


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
    # safeMode = alvo de produção (mascaramento e cautela); activeScan = pode atacar.
    # Separados porque produção verificada + opt-in explícito pode rodar o ativo.
    safeMode: bool = True
    activeScan: bool | None = None  # None mantém o comportamento antigo: ativo só fora de produção
    scannerIds: list[str] | None = None
    auth: ZapAuthConfig | None = None
    useAjaxSpider: bool = False


class ZapScanResponse(BaseModel):
    findings: list[Finding]
    alertsFound: int
    durationSeconds: float

class SastScanRequest(BaseModel):
    # { "nome_arquivo.ext": "conteúdo" }
    files: dict[str, str]

# ---------- Subfinder ----------
class SubdomainEnumRequest(BaseModel):
    domain: str


class SubdomainEnumResponse(BaseModel):
    findings: list[Finding]
    subdomainsFound: int
    durationSeconds: float