#!/usr/bin/env python3
"""Validate a completed RustD installed-stack certification report."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
from typing import Any

from certification_evidence_io import read_secure_text

MACHINE_GATES = (
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
RESOLVER_GATES = (
    "resolved.networkd.nonfatal",
    "resolved.upstream.explicit",
    "resolved.executor.bounded",
    "resolved.paths.native",
    "resolved.dns.link_flap",
    "resolved.dns.vpn_change",
    "resolved.dns.namespace",
    "resolved.dns.dnssec_rollover",
    "resolved.dns.dot_cert_fail",
    "resolved.dns.malformed",
    "resolved.dns.upstream_blackhole",
    "resolved.dns.captive_portal",
    "resolved.dns.failover_churn",
    "resolved.dns.suspend_resume",
    "resolved.resolver.resource_soak",
    "resolved.resolver.capability_bounds",
    "resolved.resolver.ownership",
    "resolved.performance.resolver",
)
STACK_GATES = (
    "paths",
    "container.user_ns",
    "container.cgroup_v2",
    *MACHINE_GATES,
    *RESOLVER_GATES,
    "performance.stack",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
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


def validate_timestamp(gate: str, record: dict[str, Any], now: int, max_age: int) -> None:
    timestamp = record.get("ts")
    if not isinstance(timestamp, int):
        fail(f"{gate}: ts must be an integer Unix timestamp")
    if timestamp > now + 300:
        fail(f"{gate}: timestamp is in the future")
    if timestamp < now - max_age:
        fail(f"{gate}: evidence is older than {max_age} seconds")


def validate_record(
    record: dict[str, Any], *, rustd_sha: str, resolved_sha: str, now: int, max_age: int
) -> dict[str, Any]:
    gate = record.get("gate")
    if not isinstance(gate, str) or gate not in STACK_GATES:
        fail(f"unknown or missing certification gate: {gate!r}")
    if record.get("status") != "pass":
        fail(f"{gate}: status must be pass")
    validate_timestamp(gate, record, now, max_age)
    detail = record.get("detail")
    if not isinstance(detail, str) or not detail.strip():
        fail(f"{gate}: non-empty detail is required")

    if gate in RESOLVER_GATES:
        if record.get("resolved_sha") != resolved_sha:
            fail(f"{gate}: resolved_sha does not match {resolved_sha}")
    else:
        if record.get("rustd_sha") != rustd_sha:
            fail(f"{gate}: rustd_sha does not match {rustd_sha}")
        if record.get("resolved_sha") != resolved_sha:
            fail(f"{gate}: resolved_sha does not match {resolved_sha}")
    return record


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

    contents = read_secure_text(options.report, "certification report")
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
            fail(f"line {number}: certification record must be an object")
        record = validate_record(
            decoded,
            rustd_sha=rustd_sha,
            resolved_sha=resolved_sha,
            now=now,
            max_age=options.max_age_seconds,
        )
        gate = record["gate"]
        if gate in records:
            fail(f"duplicate certification gate: {gate}")
        records[gate] = record

    missing = [gate for gate in STACK_GATES if gate not in records]
    if missing:
        fail(f"missing required certification gate(s): {', '.join(missing)}")

    print(
        json.dumps(
            {
                "status": "pass",
                "rustd_sha": rustd_sha,
                "resolved_sha": resolved_sha,
                "gate_count": len(STACK_GATES),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"RustD installed certification report: {error}", file=sys.stderr)
        raise SystemExit(2) from error
