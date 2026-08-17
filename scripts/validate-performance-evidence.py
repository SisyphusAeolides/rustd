#!/usr/bin/env python3
"""Validate comparative RustD stack performance evidence and emit a promotion voucher."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

REQUIRED_METRICS = (
    "boot",
    "service_ops",
    "dns_cold",
    "dns_warm",
    "recovery",
)
REQUIRED_RESOURCES = (
    "peak_rss_bytes",
    "peak_fds",
    "cpu_seconds_per_workload",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--expected-rustd-sha", required=True)
    parser.add_argument("--expected-resolved-sha", required=True)
    parser.add_argument(
        "--reference",
        default=os.environ.get("RUSTD_SYSTEMD_REF", "systemd 261"),
    )
    parser.add_argument(
        "--required-improvement-pct",
        type=float,
        default=float(os.environ.get("RUSTD_P95_IMPROVEMENT_PCT", "10")),
    )
    parser.add_argument("--require-promote", action="store_true")
    return parser.parse_args()


def fail(message: str) -> "None":
    raise ValueError(message)


def valid_sha(value: str) -> bool:
    return len(value) == 40 and all(ch in "0123456789abcdef" for ch in value)


def validate_secure_file(path: Path) -> None:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        fail(f"performance evidence is not a regular file: {path}")
    if info.st_mode & 0o022:
        fail(f"performance evidence must not be group/world writable: {path}")
    if info.st_uid != os.geteuid():
        fail(
            f"performance evidence owner uid {info.st_uid} does not match current uid {os.geteuid()}: {path}"
        )


def number(value: Any, name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        fail(f"{name} must be numeric")
    return float(value)


def main() -> int:
    options = parse_args()
    rustd_sha = options.expected_rustd_sha.strip().lower()
    resolved_sha = options.expected_resolved_sha.strip().lower()
    if not valid_sha(rustd_sha) or not valid_sha(resolved_sha):
        fail("expected commit ids must be 40-character lowercase hexadecimal SHAs")
    if options.required_improvement_pct <= 0 or options.required_improvement_pct >= 100:
        fail("required improvement percentage must be between 0 and 100")

    validate_secure_file(options.evidence)
    evidence = json.loads(options.evidence.read_text(encoding="utf-8"))
    if not isinstance(evidence, dict):
        fail("performance evidence must be a JSON object")
    if evidence.get("rustd_sha") != rustd_sha:
        fail("rustd_sha does not match the candidate")
    if evidence.get("resolved_sha") != resolved_sha:
        fail("resolved_sha does not match the pinned resolver candidate")
    if evidence.get("reference") != options.reference:
        fail(f"reference must be {options.reference!r}")
    if evidence.get("synthetic") is not False:
        fail("synthetic or unspecified baselines are not release evidence")
    if options.require_promote and evidence.get("promote") is not True:
        fail("promotion voucher is not marked promote=true")

    required_ratio = 1.0 - options.required_improvement_pct / 100.0
    metrics = evidence.get("metrics")
    if not isinstance(metrics, dict):
        fail("metrics are missing")
    normalized_metrics: dict[str, Any] = {}
    for name in REQUIRED_METRICS:
        metric = metrics.get(name)
        if not isinstance(metric, dict):
            fail(f"metric {name!r} is missing")
        candidate = number(metric.get("candidate_p95_ms"), f"{name}.candidate_p95_ms")
        baseline = number(metric.get("baseline_p95_ms"), f"{name}.baseline_p95_ms")
        samples = metric.get("samples")
        if candidate <= 0 or baseline <= 0:
            fail(f"{name}: p95 values must be positive")
        if not isinstance(samples, int) or samples < 30:
            fail(f"{name}: at least 30 paired samples are required")
        ratio = candidate / baseline
        if ratio > required_ratio:
            fail(f"{name}: p95 ratio {ratio:.4f} exceeds required {required_ratio:.4f}")
        normalized_metrics[name] = {
            "candidate_p95_ms": candidate,
            "baseline_p95_ms": baseline,
            "samples": samples,
            "candidate_to_reference_ratio": ratio,
        }

    resources = evidence.get("resources")
    if not isinstance(resources, dict):
        fail("resource measurements are missing")
    normalized_resources: dict[str, Any] = {}
    for name in REQUIRED_RESOURCES:
        resource = resources.get(name)
        if not isinstance(resource, dict):
            fail(f"resource {name!r} is missing")
        candidate = number(resource.get("candidate"), f"{name}.candidate")
        baseline = number(resource.get("baseline"), f"{name}.baseline")
        if candidate < 0 or baseline <= 0:
            fail(f"{name}: resource values are invalid")
        if candidate > baseline:
            fail(f"{name}: candidate resource use regressed")
        normalized_resources[name] = {
            "candidate": candidate,
            "baseline": baseline,
            "candidate_to_reference_ratio": candidate / baseline,
        }

    voucher = {
        "promote": True,
        "synthetic": False,
        "rustd_sha": rustd_sha,
        "resolved_sha": resolved_sha,
        "reference": options.reference,
        "required_p95_improvement_pct": options.required_improvement_pct,
        "metrics": normalized_metrics,
        "resources": normalized_resources,
    }
    print(json.dumps(voucher, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"RustD performance evidence: {error}", file=sys.stderr)
        raise SystemExit(2) from error
