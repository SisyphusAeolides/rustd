#!/usr/bin/env python3
"""Validate the installed rustd-resolved certification report for stack release."""
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
    "networkd.nonfatal",
    "upstream.explicit",
    "executor.bounded",
    "paths.native",
    "dns.link_flap",
    "dns.vpn_change",
    "dns.namespace",
    "dns.dnssec_rollover",
    "dns.dot_cert_fail",
    "dns.malformed",
    "dns.upstream_blackhole",
    "dns.captive_portal",
    "dns.failover_churn",
    "dns.suspend_resume",
    "resolver.resource_soak",
    "resolver.capability_bounds",
    "resolver.ownership",
    "performance.resolver",
)

MINIMUMS: dict[str, tuple[str, int]] = {
    "dns.link_flap": ("iterations", 50),
    "dns.vpn_change": ("iterations", 20),
    "dns.malformed": ("cases", 10_000),
    "dns.upstream_blackhole": ("iterations", 20),
    "dns.failover_churn": ("iterations", 100),
    "dns.suspend_resume": ("iterations", 10),
    "resolver.resource_soak": ("duration_seconds", 259_200),
}

RESOURCE_SOAK_BOUNDS = (
    ("peak_rss_kib", "max_rss_kib"),
    ("peak_fds", "max_fds"),
    ("peak_threads", "max_threads"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
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


def require_integer(
    record: dict[str, Any], gate: str, field: str, *, minimum: int
) -> int:
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        fail(f"{gate}: {field} must be an integer of at least {minimum}")
    return value


def validate_record(
    record: dict[str, Any], *, expected_sha: str, now: int, max_age: int
) -> dict[str, Any]:
    gate = record.get("gate")
    if not isinstance(gate, str) or gate not in REQUIRED_GATES:
        fail(f"unknown or missing resolver gate: {gate!r}")
    if record.get("status") != "pass":
        fail(f"{gate}: resolver status must be pass")
    if record.get("resolver_sha") != expected_sha:
        fail(f"{gate}: resolver_sha does not match {expected_sha}")

    timestamp = record.get("ts")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        fail(f"{gate}: ts must be an integer Unix timestamp")
    if timestamp > now + 300:
        fail(f"{gate}: resolver evidence timestamp is in the future")
    if timestamp < now - max_age:
        fail(f"{gate}: resolver evidence is older than {max_age} seconds")

    detail = record.get("detail")
    if not isinstance(detail, str) or not detail.strip():
        fail(f"{gate}: non-empty detail is required")

    normalized = {
        "gate": f"resolved.{gate}",
        "status": "pass",
        "detail": detail.strip(),
        "ts": timestamp,
        "resolved_sha": expected_sha,
    }
    minimum = MINIMUMS.get(gate)
    if minimum is not None:
        field, required = minimum
        normalized[field] = require_integer(record, gate, field, minimum=required)
    if gate == "resolver.resource_soak":
        for peak_field, bound_field in RESOURCE_SOAK_BOUNDS:
            peak = require_integer(record, gate, peak_field, minimum=0)
            bound = require_integer(record, gate, bound_field, minimum=1)
            if peak > bound:
                fail(f"{gate}: {peak_field} {peak} exceeds {bound_field} {bound}")
            normalized[peak_field] = peak
            normalized[bound_field] = bound
        normalized["samples"] = require_integer(record, gate, "samples", minimum=2)
    source = record.get("source")
    if isinstance(source, str) and source.strip():
        normalized["source"] = source.strip()
    return normalized


def main() -> int:
    options = parse_args()
    expected_sha = options.expected_resolved_sha.strip().lower()
    if not valid_sha(expected_sha):
        fail("expected resolver SHA must be a 40-character hexadecimal commit id")
    if options.max_age_seconds <= 0:
        fail("max evidence age must be positive")

    contents = read_secure_text(options.report, "resolver certification report")
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
            fail(f"line {number}: resolver evidence record must be an object")
        gate = decoded.get("gate")
        if gate not in REQUIRED_GATES:
            continue
        if gate in records:
            fail(f"duplicate resolver gate: {gate}")
        records[gate] = validate_record(
            decoded,
            expected_sha=expected_sha,
            now=now,
            max_age=options.max_age_seconds,
        )

    missing = [gate for gate in REQUIRED_GATES if gate not in records]
    if missing:
        fail(f"missing required resolver gate(s): {', '.join(missing)}")

    for gate in REQUIRED_GATES:
        print(json.dumps(records[gate], sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"RustD resolver certification evidence: {error}", file=sys.stderr)
        raise SystemExit(2) from error
