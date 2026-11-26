"""Marcação da evidência na prova de conceito (PoC).

O trecho que prova a falha vai entre ">>> " e " <<<" no texto da requisição ou da
resposta. A tela lê essa marcação, destaca a linha e o trecho exato e esconde os
marcadores (também no "Copiar"). Um formato só para todas as ferramentas.
"""

MARK_OPEN = ">>> "
MARK_CLOSE = " <<<"


def is_marked(text: str | None) -> bool:
    return bool(text) and MARK_OPEN in text and MARK_CLOSE in text


def mark_evidence(text: str | None, evidence: str | None) -> tuple[str | None, bool]:
    """(texto com a primeira ocorrência da evidência marcada, se achou).

    Procura primeiro o texto exato e depois sem diferenciar maiúsculas (cabeçalhos
    HTTP não diferenciam: "x-powered-by" e "X-Powered-By" são o mesmo).
    """
    if not text or not evidence or not evidence.strip():
        return text, False
    if is_marked(text):
        return text, True
    at = text.find(evidence)
    if at < 0:
        at = text.lower().find(evidence.lower())
    if at < 0:
        return text, False
    end = at + len(evidence)
    return text[:at] + MARK_OPEN + text[at:end] + MARK_CLOSE + text[end:], True
