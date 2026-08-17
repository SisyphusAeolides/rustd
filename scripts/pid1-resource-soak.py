#!/usr/bin/env python3
"""Installed-target 72-hour RustD PID1 resource and supervision soak."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

MIN_DURATION = 72 * 60 * 60


def run_text(args: list[str]) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def unit_main_pid(unit: str) -> int:
    output = run_text(["rustctl", "show", unit])
    for line in output.splitlines():
        if line.startswith("MainPID="):
            try:
                return int(line.split("=", 1)[1])
            except ValueError as error:
                raise RuntimeError(f"invalid MainPID line for {unit}: {line}") from error
    raise RuntimeError(f"rustctl show did not report MainPID for {unit}")


def process_metrics(pid: int) -> tuple[int, int, int]:
    status: dict[str, str] = {}
    for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            status[key] = value.strip()
    try:
        rss_kib = int(status["VmRSS"].split()[0])
        threads = int(status["Threads"])
    except (KeyError, ValueError) as error:
        raise RuntimeError("unable to read RustD PID1 RSS/thread metrics") from error
    fds = len(list(Path(f"/proc/{pid}/fd").iterdir()))
    return rss_kib, fds, threads


def check_pid1() -> None:
    if os.getpid() == 1:
        raise RuntimeError("run the soak driver as a supervised test process, not as PID1")
    executable = os.path.basename(os.readlink("/proc/1/exe"))
    if executable != "rustd":
        raise RuntimeError(f"PID1 is {executable!r}, expected rustd")


def check_manager_health(probe_command: str) -> None:
    subprocess.run(["rustctl", "--quiet", "is-active", "default.target"], check=True)
    if probe_command:
        result = subprocess.run(probe_command, shell=True, executable="/bin/bash")
        if result.returncode != 0:
            raise RuntimeError(f"functional manager probe failed with exit {result.returncode}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--duration-seconds", type=int, default=MIN_DURATION)
    parser.add_argument("--sample-seconds", type=int, default=60)
    parser.add_argument("--keeper-unit", required=True)
    parser.add_argument("--probe-command", default="")
    parser.add_argument("--load-command", required=True)
    parser.add_argument("--max-rss-kib", type=int, required=True)
    parser.add_argument("--max-fds", type=int, required=True)
    parser.add_argument("--max-threads", type=int, required=True)
    parser.add_argument("--evidence-out", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("RustD soak must run as root on the installed target")
    if args.duration_seconds < MIN_DURATION:
        raise RuntimeError(f"release soak requires at least {MIN_DURATION} seconds")
    if args.sample_seconds < 1:
        raise RuntimeError("--sample-seconds must be positive")
    for name, value in (
        ("--max-rss-kib", args.max_rss_kib),
        ("--max-fds", args.max_fds),
        ("--max-threads", args.max_threads),
    ):
        if value <= 0:
            raise RuntimeError(f"{name} must be positive")
    if not args.keeper_unit.endswith(".service"):
        raise RuntimeError("--keeper-unit must name a service unit")

    repository = args.repository.resolve()
    rustd_sha = run_text(["git", "-C", str(repository), "rev-parse", "HEAD"])
    if len(rustd_sha) != 40 or any(ch not in "0123456789abcdef" for ch in rustd_sha):
        raise RuntimeError("unable to resolve exact RustD commit SHA")
    resolved_sha = (repository / "scripts/rustd-resolved-revision.txt").read_text(
        encoding="utf-8"
    ).strip()
    if len(resolved_sha) != 40 or any(ch not in "0123456789abcdef" for ch in resolved_sha):
        raise RuntimeError("RustD resolver revision pin is not an exact commit SHA")

    check_pid1()
    check_manager_health(args.probe_command)
    subprocess.run(["rustctl", "--quiet", "is-active", args.keeper_unit], check=True)
    keeper_pid = unit_main_pid(args.keeper_unit)
    if keeper_pid <= 1:
        raise RuntimeError(f"invalid keeper MainPID: {keeper_pid}")
    if not Path(f"/proc/{keeper_pid}").exists():
        raise RuntimeError(f"keeper process {keeper_pid} is not alive before soak")

    load_process: subprocess.Popen[bytes] | None = None
    peak_rss = 0
    peak_fds = 0
    peak_threads = 0
    samples = 0
    started_wall = time.time()
    started_mono = time.monotonic()
    deadline = started_mono + args.duration_seconds

    try:
        print(f"starting sustained load: {args.load_command}", flush=True)
        load_process = subprocess.Popen(
            args.load_command,
            shell=True,
            executable="/bin/bash",
            start_new_session=True,
        )
        while True:
            now = time.monotonic()
            if now >= deadline:
                break
            if load_process.poll() is not None:
                raise RuntimeError(
                    f"sustained load command exited early with status {load_process.returncode}"
                )

            check_pid1()
            check_manager_health(args.probe_command)
            subprocess.run(["rustctl", "--quiet", "is-active", args.keeper_unit], check=True)
            current_keeper = unit_main_pid(args.keeper_unit)
            if current_keeper != keeper_pid:
                raise RuntimeError(
                    f"keeper MainPID changed during soak: {keeper_pid} -> {current_keeper}"
                )
            if not Path(f"/proc/{keeper_pid}").exists():
                raise RuntimeError(f"keeper process {keeper_pid} died during soak")

            rss_kib, fds, threads = process_metrics(1)
            samples += 1
            peak_rss = max(peak_rss, rss_kib)
            peak_fds = max(peak_fds, fds)
            peak_threads = max(peak_threads, threads)
            if rss_kib > args.max_rss_kib:
                raise RuntimeError(
                    f"RustD PID1 RSS {rss_kib} KiB exceeded bound {args.max_rss_kib} KiB"
                )
            if fds > args.max_fds:
                raise RuntimeError(f"RustD PID1 FD count {fds} exceeded bound {args.max_fds}")
            if threads > args.max_threads:
                raise RuntimeError(
                    f"RustD PID1 thread count {threads} exceeded bound {args.max_threads}"
                )
            elapsed = int(now - started_mono)
            print(
                f"soak sample={samples} elapsed={elapsed}s rss_kib={rss_kib} "
                f"fds={fds} threads={threads} keeper_pid={keeper_pid}",
                flush=True,
            )
            time.sleep(min(args.sample_seconds, max(0.0, deadline - time.monotonic())))

        check_pid1()
        check_manager_health(args.probe_command)
        subprocess.run(["rustctl", "--quiet", "is-active", args.keeper_unit], check=True)
        if unit_main_pid(args.keeper_unit) != keeper_pid:
            raise RuntimeError("keeper MainPID changed at final soak sample")
        rss_kib, fds, threads = process_metrics(1)
        peak_rss = max(peak_rss, rss_kib)
        peak_fds = max(peak_fds, fds)
        peak_threads = max(peak_threads, threads)
        if load_process.poll() is not None:
            raise RuntimeError(
                f"sustained load command exited before final sample with status {load_process.returncode}"
            )
    finally:
        if load_process is not None and load_process.poll() is None:
            try:
                os.killpg(load_process.pid, signal.SIGTERM)
                load_process.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(load_process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                load_process.wait(timeout=5)

    elapsed_seconds = int(time.monotonic() - started_mono)
    if elapsed_seconds < MIN_DURATION:
        raise RuntimeError(
            f"RustD soak elapsed only {elapsed_seconds}s; release minimum is {MIN_DURATION}s"
        )

    evidence = args.evidence_out or repository / "target/certification/rustd-72h-soak.jsonl"
    record = {
        "gate": "soak.72h",
        "status": "pass",
        "detail": (
            f"installed RustD remained PID1 under sustained user-supplied load for {elapsed_seconds} "
            f"seconds; default.target and the functional probe passed on every sample, keeper "
            f"{args.keeper_unit} retained MainPID {keeper_pid}, and PID1 peaks were RSS={peak_rss} KiB "
            f"(bound {args.max_rss_kib}), FDs={peak_fds} (bound {args.max_fds}), threads="
            f"{peak_threads} (bound {args.max_threads}), samples={samples}"
        ),
        "ts": int(time.time()),
        "started_ts": int(started_wall),
        "rustd_sha": rustd_sha,
        "resolved_sha": resolved_sha,
        "duration_seconds": elapsed_seconds,
        "source": "scripts/pid1-resource-soak.py",
    }
    evidence.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(evidence, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"RustD 72-hour soak certification passed: duration={elapsed_seconds}s evidence={evidence}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"RustD resource soak: {error}", file=sys.stderr)
        raise SystemExit(1) from error
