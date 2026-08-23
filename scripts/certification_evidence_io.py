"""Bounded, race-free reads for release certification evidence."""
from __future__ import annotations

import os
from pathlib import Path
import stat


MAX_EVIDENCE_BYTES = 16 * 1024 * 1024


def read_secure_text(path: Path, label: str) -> str:
    """Read one owner-controlled regular file without following symlinks."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError("secure evidence validation requires O_NOFOLLOW support")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"cannot securely open {label} {path}: {error}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} is not a regular file: {path}")
        if info.st_mode & 0o022:
            raise ValueError(f"{label} must not be group/world writable: {path}")
        if info.st_uid != os.geteuid():
            raise ValueError(
                f"{label} owner uid {info.st_uid} does not match current uid "
                f"{os.geteuid()}: {path}"
            )
        if info.st_size > MAX_EVIDENCE_BYTES:
            raise ValueError(f"{label} exceeds {MAX_EVIDENCE_BYTES} bytes: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_EVIDENCE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_EVIDENCE_BYTES:
                raise ValueError(f"{label} exceeds {MAX_EVIDENCE_BYTES} bytes: {path}")
        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"{label} is not valid UTF-8: {path}: {error}") from error
    finally:
        os.close(descriptor)
