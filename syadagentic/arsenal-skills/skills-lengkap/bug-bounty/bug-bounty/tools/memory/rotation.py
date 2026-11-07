"""Log rotation helpers for hunt-memory JSONL files.

Rotates a live JSONL file into numbered backups (``name.jsonl.1``,
``name.jsonl.2``, ...) once it exceeds a size cap, keeping at most
``keep`` backups. Oldest backups are dropped first.
"""

from __future__ import annotations

import os
from pathlib import Path

# Defaults: rotate at 10 MB, keep 3 backups.
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_KEEP = 3


def _backup_path(path: Path, n: int) -> Path:
    """Return the nth backup path for ``path`` (1 = most recent)."""
    return path.with_name(path.name + f".{n}")


def list_backups(path: Path, keep: int | None = None) -> list[Path]:
    """Return existing backup files for ``path``, newest first.

    ``keep`` limits how many are considered "live" backups; anything
    beyond it is reported too so callers can purge it.
    """
    backups: list[Path] = []
    n = 1
    while True:
        bp = _backup_path(path, n)
        if not bp.exists():
            break
        backups.append(bp)
        n += 1
    return backups


def total_bytes(path: Path, keep: int | None = None) -> int:
    """Total size of the live file plus all its backups."""
    total = path.stat().st_size if path.exists() else 0
    for bp in list_backups(path, keep=keep):
        try:
            total += bp.stat().st_size
        except OSError:
            pass
    return total


def rotate_if_needed(path: Path, max_bytes: int, keep: int = DEFAULT_KEEP) -> bool:
    """Rotate ``path`` if it is at or above ``max_bytes``.

    Returns True when a rotation happened. Rotation shifts every existing
    backup up by one (``.1`` -> ``.2`` -> ...), drops anything past
    ``keep``, then moves the live file to ``.1`` and starts a fresh one.
    """
    if not path.exists():
        return False
    try:
        if path.stat().st_size < max_bytes:
            return False
    except OSError:
        return False

    # Shift existing backups up, dropping the oldest.
    existing = list_backups(path, keep=keep)
    for bp in reversed(existing):
        idx = int(bp.suffix.lstrip(".")) if bp.suffix else 0
        if idx >= keep:
            _unlink(bp)
        else:
            target = _backup_path(path, idx + 1)
            _replace(bp, target)

    # Move the live file to .1.
    _replace(path, _backup_path(path, 1))
    return True


def purge_backups(path: Path, keep: int = 0) -> int:
    """Delete backups for ``path``, keeping the ``keep`` most recent.

    Returns the number of files removed.
    """
    removed = 0
    for bp in list_backups(path, keep=keep):
        idx = int(bp.suffix.lstrip(".")) if bp.suffix else 0
        if idx > keep:
            if _unlink(bp):
                removed += 1
    return removed


# ------------------------------------------------------------------ utils

def _unlink(p: Path) -> bool:
    try:
        p.unlink()
        return True
    except OSError:
        return False


def _replace(src: Path, dst: Path) -> None:
    """Rename ``src`` to ``dst``, tolerating a missing source."""
    try:
        os.replace(src, dst)
    except OSError:
        pass
