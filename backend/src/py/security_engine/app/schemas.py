from pydantic import BaseModel, Field


class Finding(BaseModel):
    title: str
    description: str | None = None
    severity: str
    tool: str = "NUCLEI"
    # pluginId do ZAP / template-id do Nuclei: o Node filtra o resultado pelo objetivo
    ruleId: str | None = None
    affectedUrl: str | None = None
    cveId: str | None = None
    cvssScore: float | None = None
    # CVSS 3.1: vetor usado no cálculo e de onde ele veio (TEMPLATE | CWE | SEVERITY)
    cvssVector: str | None = None
    cvssSource: str | None = None
    # confiança da ferramenta no achado (LOW | MEDIUM | HIGH | CONFIRMED)
    confidence: str | None = None
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
    # id da varredura no Checkop: permite cancelar (POST /scans/{jobId}/cancel)
    jobId: str | None = None
    targetUrl: str
    safeMode: bool = True
    # limite de requisições/seg contra o alvo (RF-51)
    rateLimit: int = Field(default=10, ge=1, le=100)
    tags: list[str] | None = None


class NucleiScanResponse(BaseModel):
    findings: list[Finding]
    findingsCount: int
    durationSeconds: float
    warnings: list[str] = []


# ---------- ZAP (RF-09) ----------
class ZapScanRequest(BaseModel):
    jobId: str | None = None
    targetUrl: str
    # safeMode = alvo de produção (mascaramento e cautela); activeScan = pode atacar.
    # Separados porque produção verificada + opt-in explícito pode rodar o ativo.
    safeMode: bool = True
    activeScan: bool | None = None  # None mantém o comportamento antigo: ativo só fora de produção
    # None = todos os scanners ativos; [] = nenhum (objetivo só passivo)
    scannerIds: list[str] | None = None
    auth: ZapAuthConfig | None = None
    useAjaxSpider: bool = False


class ZapScanResponse(BaseModel):
    findings: list[Finding]
    # ex.: regra beta indisponível no ZAP; o Node repassa ao usuário
    warnings: list[str] = []
    alertsFound: int
    durationSeconds: float

class SastScanRequest(BaseModel):
    # { "nome_arquivo.ext": "conteúdo" }
    files: dict[str, str]
    # idioma das mensagens das regras (preferência do usuário)
    language: str = "pt-BR"

class TranslateRequest(BaseModel):
    texts: list[str] = Field(default_factory=list, max_length=500)
    target: str = "pt-BR"

# ---------- Subfinder ----------
class SubdomainEnumRequest(BaseModel):
    domain: str


class SubdomainEnumResponse(BaseModel):
    findings: list[Finding]
    subdomainsFound: int
    durationSeconds: float