"""Parse the output of native NIST reference benchmarks (HAWK, SQIsign) and append rows to
results/sig_summary_reference.csv.

Each upstream benchmark prints results in its own format.  This script tries
several common patterns:

    HAWK bin/speed                — "<op>: <N> ns" or "<op>: <N> cyc"
    SQIsign apps/benchmark_lvlN   — "<op> | average <N> | ... (megacycles)"

You tell it which algorithm family the file is from, plus optionally a
default friendly-name prefix and a CPU MHz value (for cycle->ms conversion).
The parser emits a sig_summary_*.csv row per detected (algorithm, op) pair.

Usage:
    python parse_native_output.py --algo HAWK \
        --input hawk_speed.txt \
        --csv ../../results/sig_summary_reference.csv \
        --cpu-mhz 3200

    python parse_native_output.py --algo SQIsign \
        --input sqisign_lvl3.txt --label SQIsign-NIST-III \
        --csv ../../results/sig_summary_reference.csv \
        --cpu-mhz 3200
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Per-family parsers.  Each returns a list of dicts:
#   {"label": "Algo-Variant op", "p50_ms": float, ...}
# Only p50_ms (or mean_ms if no p50 available) is required; the rest is best
# effort.
# ---------------------------------------------------------------------------

def _row(label, *, mean_ms=None, p50_ms=None, stdev_ms=0.0, n=1):
    """Build a sig_summary CSV row from at minimum one timing value."""
    if mean_ms is None and p50_ms is None:
        return None
    v = p50_ms if p50_ms is not None else mean_ms
    return {
        "label":    label,
        "n":        n,
        "mean_ms":  mean_ms if mean_ms is not None else v,
        "stdev_ms": stdev_ms,
        "p50_ms":   p50_ms  if p50_ms  is not None else v,
        "p90_ms":   v,
        "p99_ms":   v,
        "min_ms":   v,
        "max_ms":   v,
    }


def _cycles_to_ms(cycles: float, cpu_mhz: float) -> float:
    return cycles / (cpu_mhz * 1000.0)


def parse_hawk(text: str, **kwargs) -> list[dict]:
    """HAWK Reference_Implementation/bin/speed output format:

        degree  kg(ms)   sd(us)   sf(us)   vv(us)   vf(us)
         256:     0.61    30.67    17.36    25.36    20.20
         512:     2.19    56.00    34.65    50.58    41.16
        1024:    12.19   119.14    71.07   106.80    86.84

    Column meanings (per HAWK's own header line):
      kg = keygen (ms)
      sd = sign with SHAKE        (us)   <- standard sign, we use this
      sf = sign SHAKE-less        (us)   <- experimental, skipped
      vv = verify                 (us)   <- standard verify, we use this
      vf = fast verify            (us)   <- experimental, skipped

    HAWK's output is already in ms/us, so cpu_mhz isn't needed.
    """
    rows = []
    # Match data lines like " 512:    2.19    56.00    34.65    50.58    41.16"
    pattern = re.compile(
        r"^\s*(256|512|1024)\s*:"
        r"\s+([\d.]+)"     # kg (ms)
        r"\s+([\d.]+)"     # sd (us) - sign
        r"\s+([\d.]+)"     # sf (us) - sign SHAKE-less
        r"\s+([\d.]+)"     # vv (us) - verify
        r"\s+([\d.]+)",    # vf (us) - fast verify
        re.MULTILINE)
    for m in pattern.finditer(text):
        degree = m.group(1)
        keygen_ms = float(m.group(2))   # kg column is already in ms
        sign_us   = float(m.group(3))
        verify_us = float(m.group(5))
        rows.append(_row(f"HAWK-{degree} keygen", p50_ms=keygen_ms))
        rows.append(_row(f"HAWK-{degree} sign",   p50_ms=sign_us/1000.0))
        rows.append(_row(f"HAWK-{degree} verify", p50_ms=verify_us/1000.0))
    return rows


def parse_sqisign(text: str, *, cpu_mhz: float | None = None,
                  label: str | None = None, **kwargs) -> list[dict]:
    """SQIsign apps/benchmark_lvlN output:
        SQIsign_lvl3 (10 iterations)
          keypair    | average  123.456 | stddev  ... | median  124.567 | min  ... | max  ...  (megacycles)
          sign       | average ...
          verify     | average ...

    Unit depends on the build: with a working cycle counter (x86 rdtsc, Apple
    Silicon) lines end in "(megacycles)" and --cpu-mhz is required. Built with
    -DNO_CYCLE_COUNTER (the only safe option on Raspberry Pi / Linux-arm64,
    where the bench would otherwise read PMCCNTR_EL0 and SIGILL), lines end in
    "(milliseconds)" and the values are used as-is.
    """
    is_ms = "(milliseconds)" in text
    if cpu_mhz is None and not is_ms:
        print("[!] --cpu-mhz required for SQIsign (its output is in megacycles).",
              file=sys.stderr)
        return []
    if label is None:
        print("[!] --label required for SQIsign (e.g. SQIsign-NIST-III).",
              file=sys.stderr)
        return []
    rows = []
    for line in text.splitlines():
        m = re.match(
            r"\s*(keypair|sign|verify)\s*\|\s*average\s+([\d.]+)"
            r"\s*\|\s*stddev\s+([\d.]+)"
            r"\s*\|\s*median\s+([\d.]+)", line)
        if not m:
            continue
        op = m.group(1)
        if op == "keypair":
            op = "keygen"                     # normalize to match other benches
        avg_mcyc    = float(m.group(2))
        stdev_mcyc  = float(m.group(3))
        median_mcyc = float(m.group(4))
        if is_ms:
            # NO_CYCLE_COUNTER build: values are already milliseconds
            mean_ms, p50_ms, stdev_ms = avg_mcyc, median_mcyc, stdev_mcyc
        else:
            # Convert megacycles to ms
            mean_ms  = _cycles_to_ms(avg_mcyc * 1e6, cpu_mhz)
            p50_ms   = _cycles_to_ms(median_mcyc * 1e6, cpu_mhz)
            stdev_ms = _cycles_to_ms(stdev_mcyc * 1e6, cpu_mhz)
        rows.append(_row(f"{label} {op}",
                         mean_ms=mean_ms, p50_ms=p50_ms, stdev_ms=stdev_ms))
    return rows


PARSERS = {
    "HAWK":    parse_hawk,
    "SQIsign": parse_sqisign,
}


# ---------------------------------------------------------------------------
# Upsert into sig_summary_reference.csv (label is the unique key)
# ---------------------------------------------------------------------------

def upsert_csv(csv_path: Path, new_rows: list[dict]) -> None:
    keep: dict[str, dict] = {}
    if csv_path.exists():
        with csv_path.open() as f:
            for row in csv.DictReader(f):
                keep[row["label"]] = row
    for r in new_rows:
        keep[r["label"]] = {k: str(v) for k, v in r.items()}
    if not keep:
        return
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["label", "n", "mean_ms", "stdev_ms",
                  "p50_ms", "p90_ms", "p99_ms", "min_ms", "max_ms", "mean_cycles", "median_cycles"]
    with csv_path.open("w", newline="") as f:  # cycles: from the generic harness's rows (these native ones: none)
        w = csv.DictWriter(f, fieldnames=fieldnames, restval="")
        w.writeheader()
        w.writerows(keep.values())


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--algo",  required=True, choices=list(PARSERS.keys()),
                    help="Which algorithm's output format to expect")
    ap.add_argument("--input", required=True, type=Path,
                    help="Path to the captured benchmark output file")
    ap.add_argument("--csv",   default=Path(__file__).parent.parent.parent /
                                       "results" / "sig_summary_reference.csv",
                    type=Path,
                    help="Where to upsert rows (default: IoT-PQC/results/sig_summary_reference.csv)")
    ap.add_argument("--cpu-mhz", type=float, default=None,
                    help="CPU frequency in MHz (required for HAWK + SQIsign cycle->ms conversion)")
    ap.add_argument("--label", type=str, default=None,
                    help="Friendly label override (used by SQIsign to set NIST-I / III / V)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print parsed rows without writing CSV")
    args = ap.parse_args()

    if not args.input.is_file():
        sys.exit(f"[-] input file not found: {args.input}")
    text = args.input.read_text(errors="ignore")
    parser = PARSERS[args.algo]
    rows = parser(text, cpu_mhz=args.cpu_mhz, label=args.label)
    rows = [r for r in rows if r is not None]

    if not rows:
        sys.exit(f"[-] no rows parsed from {args.input} (format mismatch? "
                 f"check the parser for {args.algo})")

    print(f"[+] parsed {len(rows)} rows from {args.input.name}:")
    for r in rows:
        print(f"    {r['label']:40s}  p50={r['p50_ms']:9.4f} ms"
              f"  mean={r['mean_ms']:9.4f} ms")

    if args.dry_run:
        print("[i] --dry-run: not writing CSV")
        return

    upsert_csv(args.csv, rows)
    print(f"[+] upserted into {args.csv}")


if __name__ == "__main__":
    main()
