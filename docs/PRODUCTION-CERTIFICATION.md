# Production Certification

RustD separates source/build correctness from permission to replace the host init
stack. A release is promotable only when the exact RustD commit and the exact
pinned RustD Resolved commit have matching installed-image, resolver, and
performance evidence.

## Exact stack identity

The resolver revision used by RustD is pinned in
`scripts/rustd-resolved-revision.txt`. Certification evidence for another
resolver revision is rejected. Machine evidence and performance evidence also
carry the RustD commit SHA, so reports cannot be reused after either repository
changes.

## Installed-image campaign

`make certify` is a release gate. It requires `RUSTD_MACHINE_EVIDENCE` (or
`--evidence`) containing passing, recent records for:

- disk-full, OOM-policy, and signal-storm fault injection;
- a 72-hour resource/lifecycle soak;
- cold boot, reboot, poweroff, rescue, emergency, manager re-exec, and rollback;
- rootful and rootless container profiles.

The validator enforces minimum iteration/duration counts, exact commit SHAs,
secure file ownership/mode, and a seven-day default maximum evidence age.

For a non-promoting diagnostic run, use:

```sh
scripts/installed-certification.sh --audit
```

## Comparative performance promotion

A release performance voucher is generated only from real paired lab evidence:

```sh
RUSTD_PERF_EVIDENCE=/path/to/performance.json \
  scripts/performance-promotion.sh --release
```

The evidence must compare the exact RustD/RustD Resolved stack against the
declared reference, use at least 30 paired samples for each latency metric, and
show at least a 10% lower p95 for cold boot, service operations, cold DNS, warm
DNS, and recovery. Peak RSS, peak descriptor use, and CPU time for the fixed
workload may not regress.

Audit mode never manufactures a baseline and never writes a promotion voucher.

Pass the generated voucher to installed certification:

```sh
RUSTD_MACHINE_EVIDENCE=/path/to/machine.jsonl \
RUSTD_PERFORMANCE_VOUCHER=/path/to/PROMOTE-....json \
  make certify
```

## Exclusive cutover

After installed certification passes on the target image, run the exclusive
cutover gate with the completed certification report and graphical attestation.
Keep an independently tested snapshot/recovery path until the cutover campaign
has completed on the actual hardware profile.

## Complete removal of systemd-libs

Replacing systemd as PID 1 and removing the `systemd` package is a different
boundary from removing `systemd-libs`. The current compatibility SONAME build
still contains fail-closed sd-bus/sd-json/sd-varlink placeholders that return
unsupported errors. Therefore the existing exclusive cutover gate deliberately
retains `systemd-libs` for third-party ABI compatibility.

A host is not eligible for complete `systemd-libs` removal until
`check-compat-closure` passes against the target executable closure with native,
behavioral implementations of the required ABI symbols. Symbol presence alone
is not sufficient.
