
SEVERITY_TO_CVSS_FALLBACK = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 3.0,
    "info": 0.0,
    "unknown": 0.0,
}

A01 = "A01:2021 – Broken Access Control"
A02 = "A02:2021 – Cryptographic Failures"
A03 = "A03:2021 – Injection"
A04 = "A04:2021 – Insecure Design"
A05 = "A05:2021 – Security Misconfiguration"
A06 = "A06:2021 – Vulnerable and Outdated Components"
A07 = "A07:2021 – Identification and Authentication Failures"
A08 = "A08:2021 – Software and Data Integrity Failures"
A09 = "A09:2021 – Security Logging and Monitoring Failures"
A10 = "A10:2021 – Server-Side Request Forgery"

# tags do Nuclei -> categoria OWASP Top 10
TAG_TO_OWASP = {
    "cve": A06,
    "default-login": A07,
    "exposed-panel": A05,
    "misconfig": A05,
    "exposure": A01,
    "config": A05,
    "takeover": A05,
    "sqli": A03,
    "xss": A03,
    "ssrf": A10,
    "rce": A03,
    "lfi": A01,
    "redirect": A01,
}

# CWE -> categoria OWASP Top 10 (usado principalmente pelos alertas do ZAP)
CWE_TO_OWASP = {
    # A01 - Broken Access Control
    "22": A01, "23": A01, "200": A01, "201": A01, "264": A01, "284": A01,
    "352": A01, "538": A01, "552": A01, "601": A01, "639": A01, "862": A01,
    "863": A01, "1275": A01,
    # A02 - Cryptographic Failures
    "319": A02, "326": A02, "327": A02, "328": A02, "311": A02,
    # A03 - Injection
    "20": A03, "74": A03, "77": A03, "78": A03, "79": A03, "89": A03,
    "90": A03, "94": A03, "95": A03, "113": A03, "643": A03, "917": A03,
    # A04 - Insecure Design
    "209": A04, "256": A04, "501": A04,
    # A05 - Security Misconfiguration
    "16": A05, "611": A05, "614": A05, "693": A05, "1004": A05, "1021": A05,
    # A06 - Vulnerable and Outdated Components
    "937": A06, "1035": A06, "1104": A06,
    # A07 - Identification and Authentication Failures
    "287": A07, "384": A07, "798": A07, "613": A07,
    # A08 - Software and Data Integrity Failures
    "345": A08, "353": A08, "502": A08, "829": A08,
    # A09 - Security Logging and Monitoring Failures
    "117": A09, "223": A09, "532": A09, "778": A09,
    # A10 - SSRF
    "918": A10,
}

DEFAULT_OWASP_CATEGORY = A06
INTRUSIVE_TAGS = ["dos", "fuzz", "intrusive"]


def _clean_cwe(value) -> str:
    return str(value).lower().replace("cwe-", "").strip()


def map_to_owasp_category(tags: list[str], cwe_ids: list[str] | None = None) -> str:
    # 1) CWE explícito é o sinal mais confiável
    for cwe in cwe_ids or []:
        category = CWE_TO_OWASP.get(_clean_cwe(cwe))
        if category:
            return category

    # 2) tags: tanto "cwe-89" (ZAP) quanto "sqli" (Nuclei)
    for tag in tags or []:
        normalized = str(tag).lower().strip()
        if normalized.startswith("cwe-"):
            category = CWE_TO_OWASP.get(_clean_cwe(normalized))
        else:
            category = TAG_TO_OWASP.get(normalized)
        if category:
            return category

    return DEFAULT_OWASP_CATEGORY


def resolve_cvss_score(classification: dict | None) -> float | None:
    if classification and classification.get("cvss-score") is not None:
        try:
            return float(classification["cvss-score"])
        except (TypeError, ValueError):
            pass
    return None


def fallback_cvss_for_severity(severity: str) -> float:
    return SEVERITY_TO_CVSS_FALLBACK.get((severity or "unknown").lower(), 0.0)