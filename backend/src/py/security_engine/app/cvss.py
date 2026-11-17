"""CVSS v3.1: nota calculada pela fórmula oficial a partir do vetor.

Especificação: https://www.first.org/cvss/v3.1/specification-document (seção 7).
A nota vem sempre de um vetor, nunca de um número fixo por severidade:
  1. vetor do próprio template (Nuclei com CVE traz o vetor do NVD);
  2. vetor padrão da classe da falha, pelo CWE (achados do ZAP);
  3. sem vetor: estimativa pela severidade (marcada como tal).
O vetor descreve a falha em si (nota base). O impacto real ainda depende do
contexto do sistema (dados tratados, exposição), que a nota base não mede.
"""

import math

# pesos da especificação 3.1
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class InvalidVectorError(ValueError):
    pass


def _roundup(value: float) -> float:
    # "Roundup" da especificação (apêndice A), sem erro de ponto flutuante
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    parts = vector.strip().split("/")
    if not parts or not parts[0].startswith("CVSS:3"):
        raise InvalidVectorError(f"Vetor CVSS 3.x inválido: {vector!r}")
    metrics = dict(part.split(":", 1) for part in parts[1:] if ":" in part)
    if any(metrics.get(key) is None for key in _REQUIRED):
        raise InvalidVectorError(f"Vetor CVSS incompleto: {vector!r}")
    return metrics


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    try:
        changed = m["S"] == "C"
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except KeyError as err:
        raise InvalidVectorError(f"Métrica desconhecida no vetor {vector!r}: {err}") from err
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(total, 10))


def rating(score: float) -> str:
    """Escala qualitativa oficial (seção 5)."""
    if score == 0:
        return "INFO"
    if score < 4:
        return "LOW"
    if score < 7:
        return "MEDIUM"
    if score < 9:
        return "HIGH"
    return "CRITICAL"


_V = "CVSS:3.1/"
# Vetor típico de cada classe (CWE), no pior caso realista sem autenticação.
# Valores alinhados ao que o NVD costuma atribuir a cada tipo de falha.
CWE_VECTORS = {
    # injeções: execução de consulta/comando/código no servidor
    "89": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # SQL Injection
    "78": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # comando do SO
    "77": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "94": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # injeção de código
    "1336": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", # SSTI
    "917": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # expression language
    # leitura de arquivos / dados do servidor
    "22": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",   # path traversal
    "611": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # XXE
    "538": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # arquivo sensível exposto (.env, .git)
    "540": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "541": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "527": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "530": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "548": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # listagem de diretório
    "918": _V + "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",  # SSRF
    # ataques que dependem da vítima clicar
    "79": _V + "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",   # XSS
    "80": _V + "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "601": _V + "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # open redirect
    "113": _V + "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # CRLF / response splitting
    "93": _V + "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "352": _V + "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",  # CSRF
    "942": _V + "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",  # CORS permissivo
    "264": _V + "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "1021": _V + "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", # clickjacking
    # exposição de informação e configuração
    "200": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # informação exposta
    "497": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # versão do servidor exposta
    "209": _V + "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # stack trace / erro detalhado
    "319": _V + "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # tráfego sem HTTPS
    "311": _V + "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "693": _V + "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",  # cabeçalho de proteção ausente
    "1004": _V + "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", # cookie sem HttpOnly
    "614": _V + "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",  # cookie sem Secure
    "1275": _V + "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", # cookie sem SameSite
}

# confiança informada pelo ZAP
CONFIDENCE_MAP = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "confirmed": "CONFIRMED"}

_FALLBACK = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.0, "INFO": 0.0}


def score_finding(severity: str, vector: str | None = None, cwe_ids: list[str] | None = None) -> dict:
    """Devolve {cvssScore, cvssVector, cvssSource, severity} para o achado.

    Informativo continua 0.0 (não é vulnerabilidade). Quando a nota sai de um
    vetor, a severidade segue a escala oficial do CVSS, para nota e rótulo
    nunca se contradizerem (ex.: "Alto" com nota 9.8).
    """
    if severity == "INFO":
        return {"cvssScore": 0.0, "cvssVector": None, "cvssSource": None, "severity": "INFO"}

    if vector:
        try:
            score = base_score(vector)
            return {"cvssScore": score, "cvssVector": vector.strip(), "cvssSource": "TEMPLATE", "severity": rating(score)}
        except InvalidVectorError:
            pass

    for cwe in cwe_ids or []:
        cwe_vector = CWE_VECTORS.get(str(cwe).upper().replace("CWE-", "").strip())
        if cwe_vector:
            score = base_score(cwe_vector)
            return {"cvssScore": score, "cvssVector": cwe_vector, "cvssSource": "CWE", "severity": rating(score)}

    return {"cvssScore": _FALLBACK.get(severity, 0.0), "cvssVector": None, "cvssSource": "SEVERITY", "severity": severity}
