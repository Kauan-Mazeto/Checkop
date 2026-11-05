import asyncio
import html
import os
import re

import httpx

# Traduz textos de regras (inglês -> PT-BR). Só o texto da regra é enviado, nunca o código do usuário.
# Sem nenhuma variável de ambiente usa o MyMemory (grátis, sem chave, com limite diário).
# DEEPL_API_KEY (chave ...:fx = plano free) tem prioridade e dá tradução melhor.
DEEPL_API_KEY = os.getenv("DEEPL_API_KEY", "")
MYMEMORY_EMAIL = os.getenv("MYMEMORY_EMAIL", "")  # opcional: sobe o limite de 5.000 para 50.000 caracteres/dia
TRANSLATE_TIMEOUT_SECONDS = 8.0
MYMEMORY_MAX_BYTES = 450  # o limite da API é 500 bytes por requisição

_cache: dict[str, str] = {}


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


async def _deepl(client: httpx.AsyncClient, text: str) -> str:
    host = "api-free.deepl.com" if DEEPL_API_KEY.endswith(":fx") else "api.deepl.com"
    resp = await client.post(
        f"https://{host}/v2/translate",
        headers={"Authorization": f"DeepL-Auth-Key {DEEPL_API_KEY}"},
        json={"text": [text], "source_lang": "EN", "target_lang": "PT-BR"},
    )
    resp.raise_for_status()
    return resp.json()["translations"][0]["text"]


async def _mymemory(client: httpx.AsyncClient, text: str) -> str:
    parts = []
    for chunk in _split_chunks(text):
        params = {"q": chunk, "langpair": "en|pt-BR"}
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


async def _translate_one(client: httpx.AsyncClient, semaphore: asyncio.Semaphore, text: str) -> None:
    async with semaphore:
        try:
            _cache[text] = await (_deepl(client, text) if DEEPL_API_KEY else _mymemory(client, text))
        except (httpx.HTTPError, ValueError, KeyError, IndexError):
            pass  # falhou: fica o texto original em inglês. Tradução nunca pode derrubar o scan.


async def translate_many(texts: set[str]) -> dict[str, str]:
    """Devolve {original: traduzido}. Falha de tradução devolve o original."""
    pending = [t for t in texts if t and t not in _cache]
    if pending:
        semaphore = asyncio.Semaphore(4)
        async with httpx.AsyncClient(timeout=TRANSLATE_TIMEOUT_SECONDS) as client:
            await asyncio.gather(*(_translate_one(client, semaphore, t) for t in pending))
    return {t: _cache.get(t, t) for t in texts}