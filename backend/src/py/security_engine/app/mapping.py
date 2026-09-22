
SEVERITY_TO_CVSS_FALLBACK = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 3.0,
    "info": 0.0,
    "unknown": 0.0,
}

TAG_TO_OWASP = {
    "cve": "A06:2021 – Vulnerable and Outdated Components",
    "default-login": "A07:2021 – Identification and Authentication Failures",
    "exposed-panel": "A05:2021 – Security Misconfiguration",
    "misconfig": "A05:2021 – Security Misconfiguration",
    "exposure": "A01:2021 – Broken Access Control",
    "config": "A05:2021 – Security Misconfiguration",
    "takeover": "A05:2021 – Security Misconfiguration",
    "sqli": "A03:2021 – Injection",
    "xss": "A03:2021 – Injection",
    "ssrf": "A10:2021 – Server-Side Request Forgery",
    "rce": "A03:2021 – Injection",
    "lfi": "A01:2021 – Broken Access Control",
    "redirect": "A01:2021 – Broken Access Control",
}

DEFAULT_OWASP_CATEGORY = "A06:2021 – Vulnerable and Outdated Components"
INTRUSIVE_TAGS = ["dos", "fuzz", "intrusive"]


def map_to_owasp_category(tags: list[str]) -> str:
    for tag in tags or []:
        category = TAG_TO_OWASP.get(tag.lower())
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