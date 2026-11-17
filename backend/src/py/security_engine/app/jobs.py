"""Cancelamento de varreduras em andamento.

O Node manda o id da varredura (jobId) em cada chamada de ferramenta. Nuclei e
ZAP da mesma varredura compartilham um Event: quando o usuário cancela, as duas
param o que estão fazendo e devolvem o que já encontraram.
"""

import asyncio

_events: dict[str, asyncio.Event] = {}
_users: dict[str, int] = {}


def acquire(job_id: str | None) -> asyncio.Event:
    """Event da varredura (um novo, solto, se não houver id)."""
    if not job_id:
        return asyncio.Event()
    event = _events.setdefault(job_id, asyncio.Event())
    _users[job_id] = _users.get(job_id, 0) + 1
    return event


def release(job_id: str | None) -> None:
    if not job_id or job_id not in _users:
        return
    _users[job_id] -= 1
    if _users[job_id] <= 0:
        _users.pop(job_id, None)
        _events.pop(job_id, None)


def cancel(job_id: str) -> bool:
    """Sinaliza o cancelamento. Devolve True se havia ferramenta rodando."""
    running = _users.get(job_id, 0) > 0
    if running:
        _events[job_id].set()
    return running
