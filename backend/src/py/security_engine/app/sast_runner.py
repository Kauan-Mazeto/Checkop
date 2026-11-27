import asyncio
import json
import os
import re
import shutil
import tempfile
import time

from .schemas import Finding, RelatedIssue
from .mapping import map_to_owasp_category
from .translator import translate_many
from .cwe_catalog import cwe_numbers, describe
from .secrets_runner import dedupe_findings, run_gitleaks
from .extra_analyzers import ExtraResult, run_extra_analyzers, semgrep_syntax_results

SEMGREP_BINARY = shutil.which("semgrep")
SAST_TIMEOUT_SECONDS = int(os.getenv("SAST_TIMEOUT_SECONDS", "300"))

# Pacotes oficiais do registro do Semgrep, mantidos pela comunidade e válidos para
# todas as linguagens que ele suporta. Juntos cobrem bem mais que o "auto"
# (que também exige métricas ligadas). Ajustável por variável de ambiente.
SAST_RULESETS = [
    r.strip()
    for r in os.getenv("SAST_RULESETS", "p/default,p/security-audit,p/secrets,p/owasp-top-ten").split(",")
    if r.strip()
]

# Regras próprias do Checkop: cobrem o que o registro gratuito deixa passar
# (Rust, Kotlin, Scala, C#, Swift, PHP, shell, Dockerfile, Terraform, HTML).
# Medido num corpus de código vulnerável: +24 falhas detectadas, 0 falso positivo
# no corpus equivalente seguro. Ficam no repositório, sem depender de internet.
CHECKOP_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules", "checkop")
if os.path.isdir(CHECKOP_RULES_DIR):
    SAST_RULESETS.append(CHECKOP_RULES_DIR)

SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}

REMEDIATION_SUGGESTIONS = {
    "sqli": "Use consultas parametrizadas (prepared statements) em vez de concatenar/interpolar a entrada do usuário na query.",
    "sql-injection": "Use consultas parametrizadas (prepared statements) em vez de concatenar/interpolar a entrada do usuário na query.",
    "xss": "Faça escape/sanitização da saída antes de inserir no HTML, ou use um template engine que escapa por padrão.",
    "command-injection": "Evite montar comandos de shell a partir de entrada do usuário; use APIs que não passem por um shell (ex.: execFile em vez de exec).",
    "path-traversal": "Valide e normalize o caminho recebido, restringindo a um diretório base conhecido (allowlist).",
    "hardcoded-secret": "Remova o segredo do código-fonte e carregue por variável de ambiente ou um cofre de segredos.",
    "eval": "Evite eval()/Function() com entrada do usuário; use parsers seguros (ex.: JSON.parse) para o caso de uso real.",
    "deserialization": "Evite desserializar dados não confiáveis; use formatos seguros (JSON) com validação de schema.",
    "ssrf": "Valide o destino da requisição contra uma allowlist de hosts/IPs permitidos antes de fazer a chamada.",
}



class SastExecutionError(Exception):
    pass


def _suggest_fix(check_id: str) -> str:
    lowered = check_id.lower()
    for key, suggestion in REMEDIATION_SUGGESTIONS.items():
        if key in lowered:
            return suggestion
    return "Revise o trecho apontado conforme a mensagem da regra e a documentação da categoria OWASP relacionada."


def _safe_relative_path(filename: str) -> str | None:
    # mantém subpastas (evita colisão de index.js) e descarta "..", "." e "/" iniciais
    parts = [p for p in filename.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or None


def _relative_to(path: str, base_dir: str) -> str:
    # o Semgrep devolve o caminho dentro da pasta temporária; mostramos só o nome enviado.
    # Sempre com "/": no Windows vinha "\" e arquivos em subpastas (.github/workflows/ci.yml)
    # não casavam com o nome enviado (sem trecho de código na tela).
    norm_path, norm_base = os.path.normcase(os.path.normpath(path)), os.path.normcase(os.path.normpath(base_dir))
    if norm_path.startswith(norm_base + os.sep):
        path = os.path.normpath(path)[len(os.path.normpath(base_dir)):]
    return path.replace("\\", "/").lstrip("/")


def _extract_snippet(content: str | None, start: int | None, end: int | None) -> str:
    # sem login no Semgrep o campo "lines" vem como "requires login"; lemos do código enviado
    if not content or not start:
        return ""
    return "\n".join(content.splitlines()[start - 1:(end or start)])


def _rule_name(check_id: str) -> str:
    return check_id.split(".")[-1].replace("-", " ").capitalize() or "Problema de segurança"


_SEVERITY_RANK = {"ERROR": 3, "WARNING": 2, "INFO": 1}


# Classe da falha: decide quando duas regras falam da MESMA vulnerabilidade.
# Primeiro pelo nome da regra (alguns pacotes trazem CWE errado nos metadados,
# ex.: "tainted-sql-string" marcada como CWE-915), depois pela família do CWE.
_CLASS_BY_RULE_NAME = [
    # antes de "segredo": as regras se chamam "hardcoded_bind_all_interfaces", "flask-debug-true"...
    ("debug", re.compile(r"debug", re.I)),
    # mesma falha de lógica apontada por regras diferentes (PMD, javac, ESLint...)
    ("equals", re.compile(r"compareobjectswithequals|useequalstocomparestrings|string-equality|reference-equality|equals-operator", re.I)),
    ("fallthrough", re.compile(r"fallthrough|fall-through|switch-sem-break|no-fallthrough|implicitswitchfallthrough", re.I)),
    ("uninitialized", re.compile(r"uninit|sem-ser-inicializada|might-not-have-been-initialized", re.I)),
    ("nullderef", re.compile(r"null-deref|nullpointer|null-pointer|ponteiro-nulo|null-property|nil-pointer|not-null-assertion", re.I)),
    ("memleak", re.compile(r"memleak|memory-leak|vazamento", re.I)),
    ("bounds", re.compile(r"arrayindexoutofbounds|out-of-bounds|index-len|off-by-one|bufferaccessoutofbounds", re.I)),
    ("bindall", re.compile(r"bind-all|bad-host|all-interfaces|host-0-0-0-0|0-0-0-0", re.I)),
    ("sqli", re.compile(r"sql|sqli|jdbc|query-injection", re.I)),
    ("xss", re.compile(r"xss|cross-site-scripting|innerhtml|raw-html|html-output|dangerouslysetinnerhtml", re.I)),
    ("integrity", re.compile(r"curl-pipe|pipe-download|download-to-shell|wget-pipe", re.I)),
    # regras de execução de comando que vêm com o CWE de eval (94): tainted-exec, exec-use, dangerous-subshell...
    ("cmd", re.compile(r"command-injection|os-command|shell-injection|subprocess|child-process|exec-detected|spawn-shell|shell-eval|"
                       r"tainted-exec|exec-use|exec-command|dangerous-exec|subshell|backtick|system-use|popen|process-start|runtime-exec", re.I)),
    ("code", re.compile(r"\beval\b|no-eval|no-implied-eval|no-new-func|eval-with-expression|code-injection|eval-use|exec-code", re.I)),
    ("rootuser", re.compile(r"user-is-root|last-user-is-root|run-as-root|dl3002|missing-user|container-runs-as-root", re.I)),
    ("path", re.compile(r"path-traversal|directory-traversal|dynamic-include|file-inclusion|\blfi\b", re.I)),
    ("ssrf", re.compile(r"ssrf|server-side-request", re.I)),
    ("deserialization", re.compile(r"deserializ|pickle|marshal|unserialize|yaml-load|readobject", re.I)),
    ("redirect", re.compile(r"open-redirect|redirect", re.I)),
    ("crypto", re.compile(r"weak-hash|password-hash|md5|sha1|insecure-hash|weak-crypto|des-|ecb", re.I)),
    ("secret", re.compile(r"hardcoded|hard-coded|secret|password|credential|api-key|private-key", re.I)),
]

_CLASS_BY_CWE = {
    "debug": {"489", "215", "11"},
    "bindall": {"605", "1327"},
    "rootuser": {"250", "269"},
    "nullderef": {"476"},
    "sqli": {"89", "564", "943"},
    "cmd": {"78", "77"},
    "code": {"94", "95", "917", "1336"},
    "xss": {"79", "80"},
    "path": {"22", "23", "73", "98"},
    "ssrf": {"918"},
    "deserialization": {"502"},
    "redirect": {"601"},
    "secret": {"798", "259", "321"},
    "crypto": {"327", "328", "916", "326"},
    "integrity": {"494"},
    "unpinned": {"829", "1357", "1104"},
    "tls": {"295"},
}

# CWE usada para título/correção quando a classe veio do nome da regra
CLASS_CANONICAL_CWE = {
    "debug": "489", "bindall": "1327", "rootuser": "250",
    "sqli": "89", "cmd": "78", "code": "94", "xss": "79", "path": "22", "ssrf": "918",
    "deserialization": "502", "redirect": "601", "secret": "798", "crypto": "327",
    "integrity": "494", "tls": "295",
}


def vulnerability_class(result: dict) -> str:
    metadata = result.get("extra", {}).get("metadata", {}) or {}
    if metadata.get("checkop_category") == "SYNTAX":
        return "syntax"  # Ruff, ESLint e o leitor do Semgrep apontando o mesmo erro de sintaxe
    rule = result.get("check_id", "").split(".")[-1].replace("_", "-")
    for name, pattern in _CLASS_BY_RULE_NAME:
        if pattern.search(rule):
            return name
    cwes = cwe_numbers(result.get("extra", {}).get("metadata", {}).get("cwe"))
    for name, family in _CLASS_BY_CWE.items():
        if any(cwe in family for cwe in cwes):
            return name
    return f"cwe-{cwes[0]}" if cwes else rule


def _span(result: dict) -> tuple[int, int]:
    start = result.get("start", {}).get("line") or 0
    return start, result.get("end", {}).get("line") or start


# Falhas de fluxo: uma regra aponta onde o valor entra no texto (String sql = "..." + nome)
# e outra onde ele é executado (jdbc.query(sql)), em linhas vizinhas. É a mesma falha.
_FLOW_CLASSES = {"sqli", "cmd", "code", "xss", "path", "ssrf", "redirect", "deserialization"}
_FLOW_SLACK = 2


# Regras de "segredo no código" que olham só o texto entre aspas (ex.: HARD_CODE_KEY-3 do
# findsecbugs acusa qualquer String com "senha"/"password") apontam o SQL que só CITA a
# coluna senha: "INSERT INTO usuarios (nome, senha) VALUES (?, ?)". Comando SQL não é
# segredo; um segredo de verdade (String senha = "123456") continua sendo apontado.
_SQL_STATEMENT = re.compile(
    r"""["'`][^"'`]*\b(select\s+.+?\s+from|insert\s+into|update\s+\S+\s+set|delete\s+from)\b""", re.I | re.S
)


# valor fixo dentro do próprio SQL ("... VALUES ('admin', 'admin123')", "SET senha = '123'"):
# aí sim tem senha no código, e o achado fica
_SQL_LITERAL_VALUE = re.compile(r"""(values\s*\([^)]*'[^'?]+'|\bset\b[^;]*=\s*'[^'?]+')""", re.I)


def _sql_mistaken_for_secret(result: dict, base_dir: str, contents: dict[str, str]) -> bool:
    # as regras do Checkop já distinguem SQL de segredo (ex.: checkop-insert-senha-fixa)
    if result.get("check_id", "").split(".")[-1].startswith("checkop-") or vulnerability_class(result) != "secret":
        return False
    lines = result.get("extra", {}).get("lines") or ""
    if not lines or lines == "requires login":
        # regras do registro sem login no Semgrep não trazem o trecho: lê do arquivo enviado
        start, end = _span(result)
        lines = _extract_snippet(contents.get(_relative_to(result.get("path", ""), base_dir)), start, end)
    return bool(_SQL_STATEMENT.search(lines)) and not _SQL_LITERAL_VALUE.search(lines)


def _dedupe_results(results: list[dict]) -> list[dict]:
    """Uma falha por (arquivo, classe, trecho). Regras de pacotes diferentes que
    apontam a mesma vulnerabilidade em linhas iguais ou sobrepostas (ex.: SQLi
    marcado nas linhas 8-11 por uma e na 11 por outras quatro) viram um achado
    só: o mais grave e, empatando, o de trecho mais preciso. Nas falhas de fluxo
    (injeção), linhas vizinhas também: montar o SQL e executá-lo é uma falha só."""
    buckets: dict[tuple, list[list[dict]]] = {}
    for result in sorted(results, key=_span):
        key = (result.get("path"), vulnerability_class(result))
        groups = buckets.setdefault(key, [])
        start, end = _span(result)
        for group in groups:
            g_start = min(_span(r)[0] for r in group)
            g_end = max(_span(r)[1] for r in group)
            # linhas sobrepostas; erro de sintaxe também em linha vizinha (o javac aponta o ; que
            # falta na linha 15, o PMD aponta a linha 16 onde tropeçou: é o mesmo erro)
            # vazamento: o Semgrep aponta a linha do malloc, o cppcheck o fim da função (até "}")
            slack = 1 if key[1] == "syntax" else 4 if key[1] == "memleak" else _FLOW_SLACK if key[1] in _FLOW_CLASSES else 0
            if start <= g_end + slack and end >= g_start - slack:
                group.append(result)
                break
        else:
            groups.append([result])

    unique = []
    for groups in buckets.values():
        for group in groups:
            best = max(
                group,
                key=lambda r: (_SEVERITY_RANK.get(r.get("extra", {}).get("severity"), 0), -(_span(r)[1] - _span(r)[0])),
            )
            sources = sorted({(r.get("extra", {}).get("metadata", {}) or {}).get("checkop_tool") or "Semgrep" for r in group})
            # a correção pronta (edição da ferramenta) vale para o grupo, mesmo que venha de outra regra
            with_edits = next((r for r in [best, *group] if _edits_of(r)), None)
            # o card mostra o trecho do grupo inteiro (ex.: linhas 10-11: monta o SQL e executa)
            g_start = min(_span(r)[0] for r in group)
            g_end = max(_span(r)[1] for r in group)
            span_update = {}
            if (g_start, g_end) != _span(best):
                span_update = {
                    "start": {**best.get("start", {}), "line": g_start},
                    "end": {**best.get("end", {}), "line": g_end},
                    # o trecho do Semgrep é só da linha da regra escolhida: recalcula pelo arquivo
                    "extra": {**best.get("extra", {}), "lines": ""},
                }
            unique.append({
                **best,
                **span_update,
                "_edits": _edits_of(with_edits) if with_edits else [],
                "_rule_count": len({r.get("check_id") for r in group}),
                "_class": vulnerability_class(best),
                "_sources": sources,
            })
    return unique


def _fix_mojibake(text):
    """O Semgrep no Windows lê o YAML das regras como cp1252: "variável" chega "variÃ¡vel"."""
    if isinstance(text, str) and ("Ã" in text or "Â" in text):
        try:
            return text.encode("cp1252").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return text
    return text


_LANG_BY_EXT = {
    "java": "java", "kt": "kotlin", "kts": "kotlin", "scala": "scala", "cs": "csharp",
    "js": "javascript", "mjs": "javascript", "cjs": "javascript", "jsx": "javascript",
    "ts": "typescript", "tsx": "typescript", "py": "python", "php": "php", "rb": "ruby", "go": "go",
    "c": "c", "h": "c", "cpp": "cpp", "cc": "cpp", "cxx": "cpp", "hpp": "cpp", "rs": "rust", "swift": "swift",
}


def _lang_key(path: str) -> str:
    """Linguagem do arquivo pela extensão (chave de checkop_fix_<linguagem>)."""
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return _LANG_BY_EXT.get(ext, ext)


# ---------- referências ----------
def cwe_url(cwe: str | int) -> str:
    return f"https://cwe.mitre.org/data/definitions/{int(cwe)}.html"


def _reference_urls(metadata: dict, cwes: list) -> list[str]:
    """Todo link disponível para o achado: o da ferramenta (doc da regra), os do registro do
    Semgrep (source, references) e, se nada disso existir, a página oficial do CWE."""
    urls: list[str] = []

    def add(value):
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str) and item.startswith(("http://", "https://")) and item not in urls:
                urls.append(item)

    add(metadata.get("checkop_url"))
    add(metadata.get("source"))
    add(metadata.get("references"))
    if not urls and cwes:
        add(cwe_url(cwes[0]))
    return urls[:3]


def with_references(text: str | None, urls: list[str]) -> str | None:
    if not urls:
        return text
    label = "Referência" if len(urls) == 1 else "Referências"
    return f"{text or ''}\n\n{label}: {' '.join(urls)}".strip()


# ---------- um achado por trecho ----------
_FINDING_SEVERITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
_CATEGORY_RANK = {"SECURITY": 5, "DEPENDENCY": 4, "LOGIC": 3, "SYNTAX": 2, "QUALITY": 1}
_REFERENCES_RE = re.compile(r"\n*\s*Refer[eê]ncias?:\s*(.+?)\s*$", re.S)


def _split_references(text: str | None) -> tuple[str, list[str]]:
    """("texto da correção", [links]) a partir de "...\\n\\nReferência(s): url url"."""
    if not text:
        return "", []
    match = _REFERENCES_RE.search(text)
    if not match:
        return text.strip(), []
    return text[:match.start()].strip(), re.findall(r"https?://\S+", match.group(1))


def _location(finding: Finding) -> tuple[str, int, int] | None:
    """(arquivo, linha inicial, linha final) de "app.py:33-35"."""
    file_path, _, lines = (finding.affectedUrl or "").rpartition(":")
    start, _, end = lines.partition("-")
    if not file_path or not start.isdigit():
        return None
    return file_path, int(start), int(end) if end.isdigit() else int(start)


# trecho maior que isso (função inteira) não junta: seriam problemas diferentes no mesmo bloco
_MERGE_MAX_SPAN = 6


def _merge_same_location(findings: list[Finding]) -> list[Finding]:
    """Regras/ferramentas diferentes que apontam o MESMO trecho (linhas iguais ou que se
    sobrepõem, ex.: 33-35 e 35) viram um card só: o problema mais grave fica como principal
    e os outros vão para `related`, com todas as referências e ferramentas juntas. Boa
    prática agrupada (várias ocorrências) fica de fora."""
    groups: list[tuple[str, int, int, list[Finding]]] = []
    alone: list[Finding] = []
    located = []
    for finding in findings:
        loc = _location(finding)
        # erro de sintaxe e boa prática ficam no próprio card: não são "outra falha" do
        # mesmo trecho de segurança (antes o erro de sintaxe sumia dentro do card de SSTI)
        separate = finding.category in ("SYNTAX", "QUALITY")
        if separate or loc is None or "ocorrências)" in finding.title or loc[2] - loc[1] >= _MERGE_MAX_SPAN:
            alone.append(finding)
        else:
            located.append((loc, finding))
    for (file_path, start, end), finding in sorted(located, key=lambda item: item[0]):
        for index, (g_file, g_start, g_end, items) in enumerate(groups):
            if g_file == file_path and start <= g_end and end >= g_start:
                items.append(finding)
                groups[index] = (g_file, min(g_start, start), max(g_end, end), items)
                break
        else:
            groups.append((file_path, start, end, [finding]))

    # Boa prática que cai na MESMA linha de uma falha de segurança/lógica (ex.: "variável não
    # usada" bem na linha do SQL montado) entra no card dessa falha, não num card à parte
    still_alone: list[Finding] = []
    for finding in alone:
        loc = _location(finding)
        host = None
        if finding.category == "QUALITY" and loc and "ocorrências)" not in finding.title:
            host = next((items for g_file, g_start, g_end, items in groups
                         if g_file == loc[0] and loc[1] <= g_end and loc[2] >= g_start), None)
        if host is not None:
            host.append(finding)
        else:
            still_alone.append(finding)
    alone = still_alone

    merged: list[Finding] = []
    for *_, items in groups:
        if len(items) == 1:
            merged.append(items[0])
            continue
        # mais grave primeiro; empatando, o que tem correção pronta ou texto específico (não o genérico)
        items.sort(key=lambda f: (
            _FINDING_SEVERITY.get(f.severity, 0), _CATEGORY_RANK.get(f.category or "", 0),
            bool(f.fixedCode), not (f.remediation or "").startswith("Revise o trecho"),
        ), reverse=True)
        main, others = items[0], items[1:]
        main_fix, urls = _split_references(main.remediation)
        tools = list(main.detectedBy or [])
        related = []
        for other in others:
            fix, other_urls = _split_references(other.remediation)
            urls += [u for u in other_urls if u not in urls]
            tools += [t for t in (other.detectedBy or []) if t not in tools]
            related.append(RelatedIssue(
                title=other.title.rsplit(" (", 1)[0], severity=other.severity, category=other.category,
                description=other.description, remediation=fix, fixedCode=other.fixedCode,
            ))
        merged.append(main.model_copy(update={
            "remediation": with_references(main_fix, urls[:8]),
            "detectedBy": tools,
            "related": related,
            "owaspUrl": main.owaspUrl or next((o.owaspUrl for o in others if o.owaspUrl), None),
        }))
    return merged + alone


# ---------- tradução do texto vindo das ferramentas ----------
# Títulos e correções do Checkop já são em português; o que vem cru das ferramentas
# (descrição do PMD, mensagem do ESLint/Ruff, resumo do OSV...) chega em inglês, às vezes
# no meio de uma frase nossa. Cada trecho é traduzido separado, sem tocar em links e código.
_EN_WORDS = {
    "the", "should", "is", "are", "be", "been", "use", "using", "not", "of", "to", "add", "with", "instead",
    "never", "missing", "this", "that", "or", "and", "for", "consider", "avoid", "unused", "defined",
    "expected", "saw", "found", "can", "must", "has", "have", "which", "an", "it", "its", "in", "on",
    "from", "statements", "expressions", "variable", "method", "function", "class", "value", "will",
    "when", "if", "does", "all", "any", "only", "after", "before", "same", "always", "there", "do", "no", "allows", "could", "may", "by", "was", "were", "replace", "remove",
}
_PT_WORDS = {
    "o", "de", "que", "não", "é", "um", "uma", "para", "com", "do", "da", "em", "os", "as", "se", "por",
    "no", "na", "mais", "ou", "ao", "pelo", "pela", "está", "são", "trecho", "código", "linha",
}
_PT_CHARS = re.compile(r"[ãõçáéíóúâêôà]", re.I)
_SEGMENT_SPLIT = re.compile(r"(?<=[.!?:])\s+|\n+")
_URL_OR_CODE = re.compile(r"https?://|^\s*[-*]?\s*[\w./-]+\s*$")


def _is_english(segment: str) -> bool:
    if _URL_OR_CODE.search(segment) or _PT_CHARS.search(segment):
        return False
    words = re.findall(r"[a-zA-Z']+", segment.lower())
    en = sum(w in _EN_WORDS for w in words)
    pt = sum(w in _PT_WORDS for w in words)
    # frase curta sem nenhuma palavra em português ("All members are static.") também conta
    return (en >= 2 and en > pt) or (en >= 1 and pt == 0 and len(words) >= 3)


def _title_base(title: str) -> str:
    """Título sem o "(arquivo:linha)" do fim, que não deve ir para a tradução."""
    return re.sub(r"\s*\([^()]*:[^()]*\)$", "", title or "")


def _english_segments(text: str | None) -> set[str]:
    return {s.strip() for s in _SEGMENT_SPLIT.split(text or "") if s.strip() and _is_english(s)}


def _translate_text(text: str | None, translations: dict[str, str]) -> str | None:
    if not text:
        return text
    for original in sorted(_english_segments(text), key=len, reverse=True):
        translated = translations.get(original)
        if translated and translated != original:
            text = text.replace(original, translated)
    return text


def _translate_title(title: str, translations: dict[str, str]) -> str:
    """Traduz o título sem mexer no "(arquivo:linha)" do fim."""
    base = _title_base(title)
    translated = translations.get(base.strip())
    return title.replace(base, translated, 1) if translated and translated != base else title


async def translate_findings(findings: list[Finding], language: str | None) -> list[Finding]:
    """Traduz os trechos em inglês de descrição e correção (uma chamada em lote, com cache)."""
    segments: set[str] = set()
    for finding in findings:
        for item in [finding, *(finding.related or [])]:
            segments |= _english_segments(item.description) | _english_segments(item.remediation)
            segments |= _english_segments(_title_base(item.title))
    if not segments:
        return findings
    translations = await translate_many(segments, language or "pt-BR")

    def update(item):
        return item.model_copy(update={
            "title": _translate_title(item.title, translations),
            "description": _translate_text(item.description, translations),
            "remediation": _translate_text(item.remediation, translations),
        })

    return [
        update(finding).model_copy(update={"related": [update(r) for r in finding.related]} if finding.related else {})
        for finding in findings
    ]


# ---------- correção adaptada ao código enviado ----------
# Edição = {sl, sc, el, ec, text}: linha/coluna de início e fim (1-based, fim exclusivo),
# trocadas por text. Vem pronta da ferramenta (fix do ESLint, do Ruff, fix/fix-regex das
# regras do Semgrep), calculada sobre o código que a pessoa colou: nada de exemplo fixo.
def _edits_of(result: dict) -> list[dict]:
    if result.get("_edits"):
        return result["_edits"]
    fix = (result.get("extra") or {}).get("fix")
    start, end = result.get("start") or {}, result.get("end") or {}
    if isinstance(fix, str) and start.get("col") and end.get("col"):
        return [{"sl": start["line"], "sc": start["col"], "el": end["line"], "ec": end["col"], "text": fix}]
    return []


_BLOCK_CONTEXT_MAX = 6


def _block_start(lines: list[str], first: int) -> int:
    """Primeira linha a mostrar no trecho corrigido: sobe até o começo do bloco.

    Sem contexto, "else desnecessário depois de return" mostrava só o "return" que sobrou.
    Sobe pelas linhas do mesmo nível de indentação e inclui o cabeçalho do bloco (o "if"),
    até _BLOCK_CONTEXT_MAX linhas acima. Por indentação, vale para qualquer linguagem.
    """
    indent = lambda text: len(text) - len(text.lstrip(" \t"))
    if not (1 <= first <= len(lines)):
        return first
    base = indent(lines[first - 1])
    start = first
    while start > 1 and first - start < _BLOCK_CONTEXT_MAX:
        previous = lines[start - 2]
        if not previous.strip():
            break
        start -= 1
        if indent(previous) < base:  # o cabeçalho do bloco (if/for/def...): inclui e para
            break
    return start


def _fixed_code(content: str | None, edits: list[dict], line: int | None, end_line: int | None) -> str | None:
    """Linhas do achado já com a correção aplicada, ou None se não houver edição válida."""
    if not content or not edits:
        return None
    lines = content.split("\n")
    starts = [0]
    for text in lines:
        starts.append(starts[-1] + len(text) + 1)

    def offset(row: int, col: int) -> int:
        row = min(max(row, 1), len(lines))
        return min(starts[row - 1] + max(col, 1) - 1, len(content))

    spans = sorted(((offset(e["sl"], e["sc"]), offset(e["el"], e["ec"]), e.get("text", "")) for e in edits), reverse=True)
    fixed = content
    last_start = len(content) + 1
    for begin, finish, text in spans:
        if finish > last_start or finish < begin:  # edições sobrepostas: não arrisca
            return None
        fixed = fixed[:begin] + text + fixed[finish:]
        last_start = begin
    first = min([line or 1] + [e["sl"] for e in edits])
    last = max([end_line or line or 1] + [e["el"] for e in edits])
    first = _block_start(lines, first)
    delta = fixed.count("\n") - content.count("\n")
    before = "\n".join(lines[first - 1:last])
    after = "\n".join(fixed.split("\n")[first - 1:max(last + delta, first)])
    return after if after.strip() != before.strip() else None


def _parse_result(result: dict, base_dir: str, contents: dict[str, str], translations: dict[str, str]) -> Finding:
    extra = result.get("extra", {})
    severity = SEVERITY_MAP.get(extra.get("severity", "INFO"), "LOW")
    metadata = {key: _fix_mojibake(value) for key, value in (extra.get("metadata", {}) or {}).items()}
    cwe_ids = metadata.get("cwe") or []
    owasp_tags = metadata.get("owasp") or []

    tags = [str(t) for t in (owasp_tags if isinstance(owasp_tags, list) else [owasp_tags])]
    owasp_category = map_to_owasp_category(tags, cwe_ids if isinstance(cwe_ids, list) else [cwe_ids])

    file_path = _relative_to(result.get("path", "arquivo"), base_dir)
    line = result.get("start", {}).get("line")
    end_line = result.get("end", {}).get("line")
    snippet = extra.get("lines", "")
    if not snippet or snippet == "requires login":
        snippet = _extract_snippet(contents.get(file_path), line, end_line)
    check_id = result.get("check_id", "")
    rule_name = _rule_name(check_id)
    message = _fix_mojibake(extra.get("message", ""))

    # título e correção pela classe da falha, não pelo nome técnico da regra. O CWE da
    # regra vale quando é da mesma classe (ex.: 98 = inclusão de arquivo, mais preciso
    # que o 22 genérico); senão entra o CWE da classe (metadados às vezes vêm errados)
    rule_cwes = cwe_numbers(cwe_ids)
    klass = result.get("_class", "")
    family = _CLASS_BY_CWE.get(klass, set())
    matching = [c for c in rule_cwes if c in family]
    canonical = CLASS_CANONICAL_CWE.get(klass)
    preferred = matching or ([canonical] if canonical else rule_cwes)
    known = describe(preferred + rule_cwes)
    owasp_category = map_to_owasp_category(tags, [f"CWE-{c}" for c in preferred + rule_cwes])
    # OWASP Top 10 é lista de riscos de segurança: erro de lógica/sintaxe/estilo não tem categoria
    if (metadata.get("checkop_category") or "SECURITY") not in ("SECURITY", "DEPENDENCY"):
        owasp_category = None
    category = metadata.get("checkop_category") or "SECURITY"
    # erro de lógica/sintaxe não tem CWE de segurança: título próprio da ferramenta
    title = known[0] if known else (metadata.get("checkop_title") or translations.get(rule_name, rule_name))
    # regra de várias linguagens pode ter a correção de cada uma (checkop_fix_java...):
    # o texto sai na linguagem do arquivo, não um genérico citando outra linguagem.
    # Texto próprio da regra (com os nomes reais do código) vale mais que o do catálogo de CWE
    lang = _lang_key(file_path)
    # A mensagem da regra pode trazer a correção depois de "@fix:". O Semgrep preenche os $X
    # da mensagem com o trecho real (nomes de variáveis, expressão), então esse texto é o mais
    # adaptado ao código enviado e vale mais que o do catálogo de CWE
    message, _, message_fix = message.partition("@fix:")
    message, message_fix = message.strip(), message_fix.strip()
    lang_fix = metadata.get(f"checkop_fix_{lang}")
    rule_fix = message_fix or _fix_mojibake(lang_fix) or None
    if not rule_fix and not known:
        rule_fix = _fix_mojibake(metadata.get("checkop_fix"))
    remediation = rule_fix or (known[1] if known else _suggest_fix(check_id))
    fixed_code = _fixed_code(contents.get(file_path), result.get("_edits") or _edits_of(result), line, end_line)
    remediation = with_references(remediation, _reference_urls(metadata, preferred + rule_cwes))
    description = _fix_mojibake(metadata.get(f"checkop_message_{lang}")) or translations.get(message, message)
    if result.get("_rule_count", 1) > 1:
        description = f"{description}\n\nConfirmado por {result['_rule_count']} regras diferentes."

    return Finding(
        title=f"{title} ({file_path}:{line})",
        description=description,
        severity=severity,
        tool="SAST",
        ruleId=check_id or None,
        category=category,
        affectedUrl=f"{file_path}:{line}" + (f"-{end_line}" if end_line and end_line != line else ""),
        cveId=None,
        cvssScore=None,
        rawRequest=None,
        rawResponse=snippet,
        remediation=remediation,
        fixedCode=fixed_code,
        detectedBy=result.get("_sources") or ["Semgrep"],
        owaspUrl=owasp_category,
    )


# Modo completo: além dos pacotes gerais, os pacotes oficiais por linguagem do registro
# (só os conferidos que existem: um pacote inexistente derruba a análise inteira).
# Inclui os pacotes dos frameworks principais de cada linguagem que existem no registro
# (conferidos em 2026-11-26): Spring/Jakarta (findsecbugs), Express e Node (expressjs,
# nodejsscan), React, Django/Flask/FastAPI, Rails (brakeman), Go/Gin/Echo (gosec) e PHP
# (phpcs-security-audit). Spring MVC, Laravel, NestJS, Next.js e ASP.NET Core não têm
# pacote (ou o pacote vem vazio): ficam com as regras do Checkop (rules/checkop/frameworks.yaml).
SEMGREP_LANGUAGE_PACKS = {
    (".py",): ["p/python", "p/flask", "p/django", "p/fastapi"],
    (".js", ".mjs", ".cjs", ".jsx"): ["p/javascript", "p/nodejs", "p/expressjs", "p/nodejsscan", "p/react"],
    (".ts", ".tsx"): ["p/typescript", "p/nodejs", "p/expressjs", "p/nodejsscan", "p/react"],
    (".java",): ["p/java", "p/findsecbugs"],
    (".kt", ".kts"): ["p/kotlin"],
    (".php",): ["p/php", "p/phpcs-security-audit"],
    (".rb",): ["p/ruby", "p/brakeman"],
    (".go",): ["p/golang", "p/gosec"],
    (".cs",): ["p/csharp"],
    (".rs",): ["p/rust"],
    (".c", ".h", ".cpp", ".cc", ".hpp"): ["p/c"],
    (".swift",): ["p/swift"],
    (".scala",): ["p/scala"],
    (".tf", ".hcl"): ["p/terraform"],
    (".yaml", ".yml"): ["p/kubernetes", "p/github-actions"],
}


# Pacotes por tema, válidos para várias linguagens (cada um traz regras de vários frameworks)
SEMGREP_TOPIC_PACKS = ["p/sql-injection", "p/command-injection", "p/xss", "p/jwt"]


def _semgrep_configs(files: dict[str, str], complete: bool) -> list[str]:
    configs = list(SAST_RULESETS)
    if complete:
        names = [name.lower() for name in files]
        has_code = False
        for extensions, packs in SEMGREP_LANGUAGE_PACKS.items():
            if any(name.endswith(extensions) for name in names):
                configs += [pack for pack in packs if pack not in configs]
                has_code = has_code or extensions not in ((".tf", ".hcl"), (".yaml", ".yml"))
        if has_code:
            configs += [pack for pack in SEMGREP_TOPIC_PACKS if pack not in configs]
        if any(name.split("/")[-1] in ("dockerfile", "containerfile") or "dockerfile" in name.split("/")[-1] for name in names):
            configs.append("p/dockerfile")
    return configs


# ferramentas que checam a sintaxe de verdade de cada linguagem
_SYNTAX_TOOLS = {
    "ShellCheck": (".sh", ".bash"), "Ruff": (".py",), "ESLint": (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"),
    "TypeScript": (".ts", ".tsx"), "javac": (".java",), "yamllint": (".yaml", ".yml"), "HTMLHint": (".html", ".htm"),
    "Checkop (JSON)": (".json",), "PMD": (".java", ".cls"),
}


def _group_quality(findings: list[Finding]) -> list[Finding]:
    """A mesma regra de boa prática no mesmo arquivo vira um achado só, com a lista de linhas
    (ex.: "variável não usada" em 7 lugares). Segurança, lógica e sintaxe ficam um por linha."""
    groups: dict[tuple, list[Finding]] = {}
    others: list[Finding] = []
    for finding in findings:
        if finding.category != "QUALITY" or not finding.ruleId:
            others.append(finding)
            continue
        file_path = (finding.affectedUrl or "").rsplit(":", 1)[0]
        groups.setdefault((finding.ruleId, file_path), []).append(finding)

    grouped = []
    for (_, file_path), items in groups.items():
        first = items[0]
        if len(items) == 1:
            grouped.append(first)
            continue
        lines = [(f.affectedUrl or "").rsplit(":", 1)[-1] for f in items]
        base_title = first.title.rsplit(" (", 1)[0]
        grouped.append(first.model_copy(update={
            "title": f"{base_title} ({file_path}: {len(items)} ocorrências)",
            "description": f"{first.description}\n\nAparece {len(items)} vezes, nas linhas {', '.join(lines)}.",
        }))
    return others + grouped


async def _run_semgrep(tmp_dir: str, configs: list[str]) -> dict:
    command = [
        SEMGREP_BINARY,
        *(f"--config={ruleset}" for ruleset in configs),
        "--json",
        "--quiet",
        "--metrics=off",  # o código do usuário nunca sai da máquina; só as regras são baixadas
        # calcula a correção (fix/fix-regex) de cada regra sobre o código enviado e devolve no
        # JSON (extra.fix); o --dryrun garante que nenhum arquivo é alterado
        "--autofix",
        "--dryrun",
        tmp_dir,
    ]
    process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SAST_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise SastExecutionError(f"O Semgrep excedeu o tempo limite de {SAST_TIMEOUT_SECONDS}s.")

    try:
        payload = json.loads(stdout.decode(errors="replace") or "{}")
    except json.JSONDecodeError:
        raise SastExecutionError(stderr.decode(errors="replace") or "Falha ao interpretar a saída do Semgrep.")

    # 0 = sem achados, 1 = achados. Qualquer outro código sem resultado é falha real
    # (ex.: sem internet para baixar as regras) e não pode virar "código limpo".
    if process.returncode not in (0, 1) and not payload.get("results"):
        error_messages = "; ".join(e.get("message", "") for e in payload.get("errors", []) if e.get("message"))
        detail = stderr.decode(errors="replace").strip() or error_messages
        raise SastExecutionError(detail or f"O Semgrep terminou com código {process.returncode}.")
    return payload


async def run_sast_scan(files: dict[str, str], language: str = "pt-BR", complete: bool = True) -> tuple[list[Finding], float, dict]:
    """files: {"nome_do_arquivo.js": "conteúdo do código", ...}

    Devolve (achados, duração, ferramentas) com ferramentas = {"used", "skipped", "warnings"}.
    """
    if not SEMGREP_BINARY:
        raise SastExecutionError("Binário 'semgrep' não encontrado no PATH do motor Python.")

    started_at = time.monotonic()

    with tempfile.TemporaryDirectory() as tmp_dir:
        contents: dict[str, str] = {}
        for filename, content in files.items():
            relative_name = _safe_relative_path(filename)  # evita path traversal no próprio upload
            if relative_name is None:
                raise SastExecutionError(f"Nome de arquivo inválido: {filename!r}")
            destination = os.path.join(tmp_dir, relative_name)
            try:
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                # newline="": grava exatamente como veio. No Windows o modo texto trocava LF por CRLF
                # e o ShellCheck acusava "carriage return" em todas as linhas do script
                with open(destination, "w", encoding="utf-8", newline="") as f:
                    f.write(content)
            except OSError as err:
                raise SastExecutionError(f"Não foi possível gravar {filename!r}: {err}") from err
            contents[relative_name] = content

        # Semgrep (segurança, todas as linguagens) + ferramentas especializadas, em paralelo
        payload, extra = await asyncio.gather(
            _run_semgrep(tmp_dir, _semgrep_configs(contents, complete)),
            run_extra_analyzers(tmp_dir, contents, complete),
        )
        extra: ExtraResult

        # o leitor do Semgrep aponta a linha errada quando não entende o arquivo; se a linguagem
        # tem ferramenta própria de sintaxe (ShellCheck, Ruff, ESLint, javac...), vale a dela
        covered = {ext for tool, exts in _SYNTAX_TOOLS.items() if tool in extra.used for ext in exts}
        generic_syntax = [r for r in semgrep_syntax_results(payload) if not str(r.get("path", "")).lower().endswith(tuple(covered))]
        results = payload.get("results", []) + generic_syntax + extra.results
        results = _dedupe_results([r for r in results if not _sql_mistaken_for_secret(r, tmp_dir, contents)])
        texts = {_rule_name(r.get("check_id", "")) for r in results}
        texts |= {r.get("extra", {}).get("message", "") for r in results}
        translations = await translate_many(texts, language)

        findings = _group_quality([_parse_result(r, tmp_dir, contents, translations) for r in results])
        # segredos fixos (chaves, tokens) em qualquer linguagem; ainda dentro da pasta temporária
        findings += await run_gitleaks(tmp_dir, contents)
        # dependências vulneráveis (OSV-Scanner) já vêm prontas
        findings += extra.findings
        findings = _merge_same_location(findings)
        findings = await translate_findings(findings, language)
        duration = time.monotonic() - started_at
        broken = sorted({(f.affectedUrl or "").rsplit(":", 1)[0] for f in findings if f.category == "SYNTAX"} - {""})
        if broken:
            extra.warnings.insert(0, (
                f"Há erro de sintaxe em {', '.join(broken)}. Compiladores e analisadores que precisam ler o arquivo "
                "inteiro param no primeiro erro, então alguns problemas só aparecem "
                "depois que a sintaxe for corrigida. Corrija e analise de novo."
            ))
        tools = {
            "depth": "COMPLETE" if complete else "ESSENTIAL",
            "used": ["Semgrep", "Gitleaks", *sorted(set(extra.used))],
            "skipped": sorted(set(extra.skipped)),
            "warnings": extra.warnings,
        }
        return dedupe_findings(findings), duration, tools
