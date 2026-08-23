#!/usr/bin/env python3
"""Validate installed-image RustD release evidence."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
from typing import Any

from certification_evidence_io import read_secure_text

REQUIRED_GATES = (
    "fault.disk_full_sim",
    "fault.oom_policy",
    "fault.signal_storm",
    "soak.72h",
    "boot.cold",
    "boot.reboot",
    "boot.poweroff",
    "boot.rescue",
    "boot.emergency",
    "boot.reexec",
    "boot.rollback",
    "container.rootful",
    "container.rootless",
)

MINIMUMS: dict[str, tuple[str, int]] = {
    "fault.disk_full_sim": ("iterations", 3),
    "fault.oom_policy": ("iterations", 10),
    "fault.signal_storm": ("iterations", 1_000),
    "soak.72h": ("duration_seconds", 259_200),
    "boot.cold": ("iterations", 3),
    "boot.reboot": ("iterations", 10),
    "boot.poweroff": ("iterations", 10),
    "boot.rescue": ("iterations", 3),
    "boot.emergency": ("iterations", 3),
    "boot.reexec": ("iterations", 100),
    "boot.rollback": ("iterations", 3),
    "container.rootful": ("iterations", 10),
    "container.rootless": ("iterations", 10),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--expected-rustd-sha", required=True)
    parser.add_argument("--expected-resolved-sha", required=True)
    parser.add_argument(
        "--max-age-seconds",
        type=int,
        default=int(os.environ.get("RUSTD_CERT_MAX_EVIDENCE_AGE", "604800")),
    )
    return parser.parse_args()


def fail(message: str) -> "None":
    raise ValueError(message)


def valid_sha(value: str) -> bool:
    return len(value) == 40 and all(ch in "0123456789abcdef" for ch in value)


def validate_record(
    record: dict[str, Any],
    *,
    expected_rustd_sha: str,
    expected_resolved_sha: str,
    now: int,
    max_age: int,
) -> dict[str, Any]:
    gate = record.get("gate")
    if not isinstance(gate, str) or gate not in REQUIRED_GATES:
        fail(f"unknown or missing gate: {gate!r}")
    if record.get("status") != "pass":
        fail(f"{gate}: status must be pass")
    if record.get("rustd_sha") != expected_rustd_sha:
        fail(f"{gate}: rustd_sha does not match {expected_rustd_sha}")
    if record.get("resolved_sha") != expected_resolved_sha:
        fail(f"{gate}: resolved_sha does not match {expected_resolved_sha}")

    timestamp = record.get("ts")
    if not isinstance(timestamp, int):
        fail(f"{gate}: ts must be an integer Unix timestamp")
    if timestamp > now + 300:
        fail(f"{gate}: evidence timestamp is in the future")
    if timestamp < now - max_age:
        fail(f"{gate}: evidence is older than {max_age} seconds")

    field, required = MINIMUMS[gate]
    value = record.get(field)
    if not isinstance(value, int) or value < required:
        fail(f"{gate}: {field} must be at least {required}")

    detail = record.get("detail")
    if not isinstance(detail, str) or not detail.strip():
        fail(f"{gate}: non-empty detail is required")

    normalized = {
        "gate": gate,
        "status": "pass",
        "detail": detail.strip(),
        "ts": timestamp,
        "rustd_sha": expected_rustd_sha,
        "resolved_sha": expected_resolved_sha,
        field: value,
    }
    source = record.get("source")
    if isinstance(source, str) and source.strip():
        normalized["source"] = source.strip()
    return normalized


def main() -> int:
    options = parse_args()
    rustd_sha = options.expected_rustd_sha.strip().lower()
    resolved_sha = options.expected_resolved_sha.strip().lower()
    if not valid_sha(rustd_sha):
        fail("expected RustD SHA must be a 40-character hexadecimal commit id")
    if not valid_sha(resolved_sha):
        fail("expected resolver SHA must be a 40-character hexadecimal commit id")
    if options.max_age_seconds <= 0:
        fail("max evidence age must be positive")

    contents = read_secure_text(options.evidence, "evidence")
    now = int(time.time())
    records: dict[str, dict[str, Any]] = {}
    for number, raw in enumerate(contents.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as error:
            fail(f"line {number}: invalid JSON: {error}")
        if not isinstance(decoded, dict):
            fail(f"line {number}: evidence record must be an object")
        record = validate_record(
            decoded,
            expected_rustd_sha=rustd_sha,
            expected_resolved_sha=resolved_sha,
            now=now,
            max_age=options.max_age_seconds,
        )
        gate = record["gate"]
        if gate in records:
            fail(f"duplicate gate: {gate}")
        records[gate] = record

    missing = [gate for gate in REQUIRED_GATES if gate not in records]
    if missing:
        fail(f"missing required gate(s): {', '.join(missing)}")

    for gate in REQUIRED_GATES:
        print(json.dumps(records[gate], sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"RustD certification evidence: {error}", file=sys.stderr)
        raise SystemExit(2) from error
