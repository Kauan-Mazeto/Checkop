"""Configuração local do motor, carregada antes de qualquer outro módulo.

1. Lê o backend/.env (o mesmo da API Node), para ENGINE_TOKEN, ZAP_API_URL e
   ZAP_API_KEY não precisarem ser definidos à mão em cada terminal. Variáveis
   já definidas no ambiente têm prioridade (o .env nunca sobrescreve).
2. Acha nuclei/subfinder em backend/tools/ quando não estão no PATH.
"""

import os
import shutil
from pathlib import Path

_HERE = Path(__file__).resolve()


def _find_backend_dir() -> Path:
    """Pasta backend/ (a que tem package.json e src/py) subindo a partir deste arquivo.

    No Docker o motor fica sozinho em /app/app, sem a árvore do backend: aí não há
    .env nem tools/ para procurar (as variáveis vêm do compose e as ferramentas
    estão no PATH da imagem). Antes era parents[4] fixo, que não existe nesse
    layout e derrubava o motor na largada com IndexError.
    """
    for folder in _HERE.parents:
        if (folder / "package.json").is_file() and (folder / "src" / "py").is_dir():
            return folder
    return _HERE.parent


BACKEND_DIR = _find_backend_dir()
TOOLS_DIR = BACKEND_DIR / "tools"


def _parse_env_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    key, value = line.split("=", 1)
    key = key.strip().removeprefix("export ").strip()
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return (key, value) if key else None


def load_env_file(path: Path = BACKEND_DIR / ".env") -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        parsed = _parse_env_line(line)
        if parsed and parsed[0] not in os.environ:
            os.environ[parsed[0]] = parsed[1]


def find_tool(name: str) -> str | None:
    """Binário no PATH ou em backend/tools/<nome>/<nome>(.exe)."""
    found = shutil.which(name)
    if found:
        return found
    for candidate in (TOOLS_DIR / name / f"{name}.exe", TOOLS_DIR / name / name):
        if candidate.is_file():
            return str(candidate)
    return None


load_env_file()
