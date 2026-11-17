import asyncio
import html
import os
import re

import httpx

# Traduz textos de regras (inglês -> idioma escolhido pelo usuário). Só o texto da
# regra é enviado, nunca o código do usuário.
# Sem nenhuma variável de ambiente usa o MyMemory (grátis, sem chave, com limite diário).
# DEEPL_API_KEY (chave ...:fx = plano free) tem prioridade e dá tradução melhor.
DEEPL_API_KEY = os.getenv("DEEPL_API_KEY", "")
MYMEMORY_EMAIL = os.getenv("MYMEMORY_EMAIL", "")  # opcional: sobe o limite de 5.000 para 50.000 caracteres/dia
TRANSLATE_TIMEOUT_SECONDS = 8.0
MYMEMORY_MAX_BYTES = 450  # o limite da API é 500 bytes por requisição
SOURCE_LANGUAGE = "en"  # ZAP, Nuclei e Semgrep publicam as regras em inglês
DEFAULT_TARGET = "pt-BR"

# códigos aceitos (BCP 47 simples): "pt-BR", "es", "fr", "zh-CN"...
_LANGUAGE_RE = re.compile(r"^[a-z]{2,3}(-[a-z]{2,4})?$")

# idiomas que o DeepL exige com variante
_DEEPL_VARIANTS = {"pt": "PT-BR", "en": "EN-US", "zh": "ZH-HANS"}

_cache: dict[tuple[str, str], str] = {}


class UnsupportedLanguageError(ValueError):
    pass


def normalize_language(language: str | None) -> str:
    value = (language or DEFAULT_TARGET).strip()
    if not _LANGUAGE_RE.match(value.lower()):
        raise UnsupportedLanguageError(f"Idioma inválido: {language!r}.")
    base, _, region = value.partition("-")
    return f"{base.lower()}-{region.upper()}" if region else base.lower()


def is_source_language(language: str) -> bool:
    return language.split("-")[0] == SOURCE_LANGUAGE


def _deepl_target(language: str) -> str:
    base = language.split("-")[0]
    if "-" in language and base in ("pt", "en", "zh"):
        return language.upper() if base != "zh" else _DEEPL_VARIANTS["zh"]
    return _DEEPL_VARIANTS.get(base, base.upper())


def _split_chunks(text: str, limit: int = MYMEMORY_MAX_BYTES) -> list[str]:
    chunks: list[str] = []
    current = ""
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        while len(sentence.encode("utf-8")) > limit:  # frase gigante: corta no meio
            cut = limit // 4
            if current:
                chunks.append(current)
                current = ""
            chunks.append(sentence[:cut])
            sentence = sentence[cut:]
        candidate = f"{current} {sentence}".strip()
        if len(candidate.encode("utf-8")) <= limit:
            current = candidate
        else:
            chunks.append(current)
            current = sentence
    if current:
        chunks.append(current)
    return chunks


async def _deepl(client: httpx.AsyncClient, text: str, target: str) -> str:
    host = "api-free.deepl.com" if DEEPL_API_KEY.endswith(":fx") else "api.deepl.com"
    resp = await client.post(
        f"https://{host}/v2/translate",
        headers={"Authorization": f"DeepL-Auth-Key {DEEPL_API_KEY}"},
        json={"text": [text], "source_lang": SOURCE_LANGUAGE.upper(), "target_lang": _deepl_target(target)},
    )
    resp.raise_for_status()
    return resp.json()["translations"][0]["text"]


async def _mymemory(client: httpx.AsyncClient, text: str, target: str) -> str:
    parts = []
    for chunk in _split_chunks(text):
        params = {"q": chunk, "langpair": f"{SOURCE_LANGUAGE}|{target}"}
        if MYMEMORY_EMAIL:
            params["de"] = MYMEMORY_EMAIL
        resp = await client.get("https://api.mymemory.translated.net/get", params=params)
        resp.raise_for_status()
        data = resp.json()
        translated = html.unescape(data["responseData"]["translatedText"])
        # cota estourada ou erro: a API responde com um aviso no lugar da tradução
        if str(data.get("responseStatus")) != "200" or "MYMEMORY WARNING" in translated.upper():
            raise ValueError("MyMemory não traduziu (cota diária ou erro).")
        parts.append(translated)
    return " ".join(parts)


async def _translate_one(client: httpx.AsyncClient, semaphore: asyncio.Semaphore, text: str, target: str) -> None:
    async with semaphore:
        try:
            translated = await (_deepl(client, text, target) if DEEPL_API_KEY else _mymemory(client, text, target))
        except (httpx.HTTPError, ValueError, KeyError, IndexError):
            return  # falhou: fica o texto original. Tradução nunca pode derrubar o scan.
        if translated.strip():
            _cache[(target, text)] = translated


DEEPL_BATCH_SIZE = 50  # limite da API por requisição
DEEPL_BATCH_TIMEOUT_SECONDS = 20.0


async def _deepl_batch(client: httpx.AsyncClient, texts: list[str], target: str) -> None:
    host = "api-free.deepl.com" if DEEPL_API_KEY.endswith(":fx") else "api.deepl.com"
    try:
        resp = await client.post(
            f"https://{host}/v2/translate",
            headers={"Authorization": f"DeepL-Auth-Key {DEEPL_API_KEY}"},
            json={"text": texts, "source_lang": SOURCE_LANGUAGE.upper(), "target_lang": _deepl_target(target)},
            timeout=DEEPL_BATCH_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        results = resp.json()["translations"]
    except (httpx.HTTPError, ValueError, KeyError):
        return  # falhou: ficam os originais
    for original, item in zip(texts, results):
        translated = (item or {}).get("text", "")
        if translated.strip():
            _cache[(target, original)] = translated


async def translate_many(texts: set[str], target: str = DEFAULT_TARGET) -> dict[str, str]:
    """Devolve {original: traduzido}. Falha de tradução devolve o original."""
    target = normalize_language(target)
    if is_source_language(target):
        return {t: t for t in texts}
    pending = [t for t in texts if t and (target, t) not in _cache]
    if pending:
        async with httpx.AsyncClient(timeout=TRANSLATE_TIMEOUT_SECONDS) as client:
            if DEEPL_API_KEY:
                # DeepL: lotes de até 50 textos numa requisição só, em paralelo
                batches = [pending[i:i + DEEPL_BATCH_SIZE] for i in range(0, len(pending), DEEPL_BATCH_SIZE)]
                await asyncio.gather(*(_deepl_batch(client, batch, target) for batch in batches))
            else:
                semaphore = asyncio.Semaphore(4)
                await asyncio.gather(*(_translate_one(client, semaphore, t, target) for t in pending))
    return {t: _cache.get((target, t), t) for t in texts}
