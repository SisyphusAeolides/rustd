#!/usr/bin/env python3
"""Exercise the fail-closed resolver report importer contract."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
VALIDATOR = ROOT / "scripts/validate-resolver-certification-report.py"
REVISION = "a" * 40
GATES = (
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
MINIMUMS = {
    "dns.link_flap": ("iterations", 50),
    "dns.vpn_change": ("iterations", 20),
    "dns.malformed": ("cases", 10_000),
    "dns.upstream_blackhole": ("iterations", 20),
    "dns.failover_churn": ("iterations", 100),
    "dns.suspend_resume": ("iterations", 10),
    "resolver.resource_soak": ("duration_seconds", 259_200),
}


def records() -> list[dict[str, object]]:
    timestamp = int(time.time())
    result: list[dict[str, object]] = []
    for gate in GATES:
        record: dict[str, object] = {
            "gate": gate,
            "status": "pass",
            "detail": "installed resolver campaign passed",
            "ts": timestamp,
            "resolver_sha": REVISION,
            "source": "installed-campaign",
        }
        if gate in MINIMUMS:
            field, minimum = MINIMUMS[gate]
            record[field] = minimum
        if gate == "resolver.resource_soak":
            record.update(
                peak_rss_kib=1024,
                max_rss_kib=2048,
                peak_fds=8,
                max_fds=16,
                peak_threads=4,
                max_threads=8,
                samples=2,
            )
        result.append(record)
    return result


def validate(candidate: list[dict[str, object]], *, succeeds: bool) -> None:
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as evidence:
        for record in candidate:
            evidence.write(json.dumps(record, sort_keys=True) + "\n")
        evidence.flush()
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), evidence.name, "--expected-resolved-sha", REVISION],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if (result.returncode == 0) != succeeds:
        raise SystemExit(
            f"resolver report validator unexpectedly returned {result.returncode}"
        )


def main() -> int:
    baseline = records()
    validate(baseline, succeeds=True)
    for gate, (field, minimum) in MINIMUMS.items():
        candidate = [record.copy() for record in baseline]
        next(record for record in candidate if record["gate"] == gate)[field] = minimum - 1
        validate(candidate, succeeds=False)
    candidate = [record.copy() for record in baseline]
    soak = next(record for record in candidate if record["gate"] == "resolver.resource_soak")
    soak["peak_rss_kib"] = int(soak["max_rss_kib"]) + 1
    validate(candidate, succeeds=False)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        report = root / "report.jsonl"
        report.write_text(
            "".join(json.dumps(record, sort_keys=True) + "\n" for record in baseline),
            encoding="utf-8",
        )
        link = root / "report-link.jsonl"
        link.symlink_to(report)
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(link), "--expected-resolved-sha", REVISION],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            raise SystemExit("resolver report validator followed a symlink")
    print("resolver certification importer contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
