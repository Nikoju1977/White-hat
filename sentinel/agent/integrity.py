"""Opt-in, bounded file integrity monitoring. No file contents leave the endpoint.

Paths come exclusively from the endpoint administrator's environment; never from
network input. Initial baseline creates no alert. A missing/unreadable file is
marked unknown rather than automatically treated as an attack.
"""
import hashlib
import os
from pathlib import Path

MAX_FILES = 20
MAX_BYTES = 8 * 1024 * 1024


def file_hash(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_BYTES:
            return None
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(65536), b''):
                digest.update(block)
        return digest.hexdigest()
    except (OSError, ValueError):
        return None


def monitor(paths: str, state: dict) -> tuple[list[dict], dict]:
    old = state.get('fim', {}) if isinstance(state.get('fim'), dict) else {}
    current = dict(old)
    alerts: list[dict] = []
    unique = list(dict.fromkeys(s.strip() for s in paths.split(os.pathsep) if s.strip()))[:MAX_FILES]
    for raw in unique:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            continue
        key = str(p)
        observed = file_hash(p)
        if observed is None:
            # No negative assertion when privilege or size prevents inspection.
            continue
        previous = old.get(key)
        if previous and previous != observed:
            alerts.append({'source': 'fim', 'signature': f'Empreinte modifiée : {p.name}'[:250],
                           'id': hashlib.sha256(key.encode()).hexdigest()[:32], 'severity': 'medium'})
        current[key] = observed
    return alerts, current
