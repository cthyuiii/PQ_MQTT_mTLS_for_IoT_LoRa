"""Build + run NIST reference-implementation signature benchmarks.

Polyglot approach: every algorithm's NIST submission ships a C reference
implementation with the same api.h (CRYPTO_PUBLICKEYBYTES, crypto_sign_keypair,
crypto_sign, crypto_sign_open).  We compile bench_template.c against each
algo's reference .c files, run the resulting binary, and aggregate the timing
output into one CSV (the percentile schema to_customer_form.py --summary reads).

Workflow:
    1.  Download each algorithm's NIST round-2 submission package into
        reference/<ALGO>/  (see algos.json for URLs).
    2.  Run this script.  It walks algos.json, finds the variants in each
        algo's directory, builds bench_template.c against them, runs the
        binary, and writes:
            results/sig_summary_reference.csv    (percentile table)
            results/sig_raw_reference.csv        (per-iteration latencies)
            results/sig_meta_reference.csv       (pk/sig/sk sizes per variant)

Usage examples:
    python run_reference_benchmarks.py                     # build + run all
    python run_reference_benchmarks.py --algos HAWK        # just HAWK
    python run_reference_benchmarks.py --probe-only        # build only,
                                                           # populate meta
    python run_reference_benchmarks.py --iterations 50     # smaller n
    python run_reference_benchmarks.py --variants HAWK-512 # specific variant

Notes for Apple Silicon:
    - Most NIST reference impls assume gcc-style flags; clang works fine.
    - Some need OpenSSL (FAEST uses libcrypto for AES-NI fallback).  Install
      with `brew install openssl@3` and pass include path if cc can't find it.
    - SQIsign has its own CMake build; the runner detects CMakeLists.txt and
      invokes cmake/ninja instead of plain cc.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
BENCH_C = HERE / "bench_template.c"
ALGOS_JSON = HERE / "algos.json"
# Default results dir is IoT-PQC/results/ - two levels up from
# signatures/reference/run_reference_benchmarks.py.
DEFAULT_RESULTS = HERE.parent.parent / "results"
# setup_round3.sh builds the round 3 code out of the repo; algos.json writes that place as {CACHE}
CACHE = os.environ.get("IOT_PQC_CACHE", os.path.expanduser("~/.cache/iot-pqc"))
def _cache(x: str) -> str:
    return x.replace("{CACHE}", CACHE)


# ---------------------------------------------------------------------------
# Discovery + build
# ---------------------------------------------------------------------------

def _find_compiler() -> str:
    """Pick a C compiler that's actually on PATH."""
    for c in ("cc", "gcc", "clang"):
        if shutil.which(c):
            return c
    sys.exit("[-] no C compiler found on PATH (cc / gcc / clang)")


def _gather_sources(variant_dir: Path, extra_sources: list[str],
                    include_subdirs: list[str] | None = None,
                    exclude_files: list[str] | None = None) -> list[Path]:
    """Return *.c in variant_dir plus *.c from any include_subdirs and any
    explicitly named extras.  exclude_files skips files (e.g. another main())
    that would conflict with bench_template.c's main()."""
    excludes = set(exclude_files or [])
    sources = [p for p in sorted(variant_dir.glob("*.c")) if p.name not in excludes]
    for sub in include_subdirs or []:
        sub_dir = variant_dir / sub
        if sub_dir.is_dir():
            for p in sorted(sub_dir.glob("*.c")):
                if p.name not in excludes:
                    sources.append(p)
        else:
            print(f"    [!] include_subdir not found: {sub}")
    for extra in extra_sources or []:
        p = (variant_dir / extra).resolve()
        if p.exists():
            sources.append(p)
        else:
            print(f"    [!] extra source not found: {extra}")
    return sources


def build_variant(algo_name: str, variant_cfg: dict, *, compiler: str,
                  verbose: bool = False) -> Path | None:
    """Compile bench_template.c with this variant's reference sources.
    Returns the built executable path, or None on failure / unsupported strategy."""
    # Algos with non-generic build systems (HAWK / MQOM / FAEST / SQIsign / QR-UOV)
    # are skipped here with a pointer to their native-benchmark recipe in README.md.
    strategy = variant_cfg.get("_build_strategy", "generic-bench")
    name = variant_cfg["name"]
    if strategy != "generic-bench":
        print(f"    [SKIP] {name}: build_strategy='{strategy}'. "
              f"Use the algorithm's native benchmark per README.md and append "
              f"the row to results/sig_summary_reference.csv by hand.")
        return None

    variant_dir = HERE / variant_cfg.get("_resolved_dir", "")
    if not variant_dir.is_dir():
        print(f"    [SKIP] {name}: directory missing  ({variant_dir})")
        return None
    if not (variant_dir / "api.h").exists():
        print(f"    [SKIP] {name}: no api.h in {variant_dir.name}")
        return None

    include_subdirs = variant_cfg.get("include_subdirs", [])
    exclude_files   = variant_cfg.get("exclude_files", [])
    sources = _gather_sources(variant_dir,
                              variant_cfg.get("extra_sources", []),
                              include_subdirs=include_subdirs,
                              exclude_files=exclude_files)
    if not sources:
        print(f"    [SKIP] {name}: no .c files in {variant_dir}")
        return None

    # ---- Auto-extract -D flags from the variant's own Makefile ----
    # Many NIST submissions (SDitH, MQOM, etc.) configure their parameter
    # set via -DPARAM_<X> -DPARAM_L<N> -DPARAM_<FIELD>.  Reading those out
    # of the upstream Makefile beats per-variant config in algos.json and
    # survives upstream parameter additions.
    auto_defines = []
    makefile = variant_dir / "Makefile"
    if makefile.is_file():
        try:
            mk_text = makefile.read_text(errors="ignore")
            auto_defines = sorted(set(re.findall(r"-D[A-Z][A-Z0-9_]+(?:=\w+)?", mk_text)))
        except OSError:
            pass

    bench_exe = variant_dir / "bench"
    # -std=gnu11 (not gnu99) so C11 functions like aligned_alloc resolve
    # without -Werror=implicit-function-declaration tripping.  Most NIST
    # submissions are C11.
    cmd = [compiler, "-O3", "-std=gnu11",
           "-Wno-error",
           "-Wno-implicit-function-declaration",
           f"-I{variant_dir}"]
    # Auto-add -I for every include_subdir (so headers like sha3/KeccakHash.h
    # resolve as both `#include "KeccakHash.h"` and `#include "sha3/KeccakHash.h"`).
    for sub in include_subdirs:
        cmd.append(f"-I{variant_dir / sub}")
    cmd += auto_defines                            # extracted from Makefile
    cmd.append(str(BENCH_C))
    cmd += [str(s) for s in sources]
    cmd += [_cache(f) for f in variant_cfg.get("extra_cflags", [])]
    if sys.platform == "darwin":  # Apple clang has no OpenMP (QR-UOV's -fopenmp is for the Pi's gcc), and macOS
        cmd = [c for c in cmd if c != "-fopenmp"] + ["-Dexplicit_bzero=bzero"]  # no explicit_bzero (QR-UOV round 3)
    cmd += ["-o", str(bench_exe)]
    cmd += [_cache(f) for f in variant_cfg.get("extra_ldflags", ["-lm"])]
    if variant_cfg.get("ldflags_file"):  # flags that differ per machine (SQIsign's archives: setup_round3.sh)
        cmd += Path(_cache(variant_cfg["ldflags_file"])).read_text().split()
    if verbose and auto_defines:
        print(f"    [defines] {' '.join(auto_defines)}")

    if verbose:
        print(f"    [cmd] {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        head = (e.stderr or "")[:800]
        print(f"    [FAIL] {name}: build error\n      {head.strip()[:600]}")
        return None
    return bench_exe


def run_variant(exe: Path, label: str, iters: int, warmup: int,
                timeout_s: int = 600) -> tuple[list[dict], dict | None]:
    """Run a built bench executable; return (raw_rows, meta_dict_or_None)."""
    try:
        # one thread, as every other bench: QR-UOV's '#pragma omp parallel for' would otherwise use all cores
        result = subprocess.run([str(exe), label, str(iters), str(warmup)], env=dict(os.environ, OMP_NUM_THREADS="1"),
                                capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        print(f"    [FAIL] {label}: timed out after {timeout_s}s")
        return [], None
    if result.returncode != 0:
        print(f"    [FAIL] {label}: rc={result.returncode}")
        print(f"      stderr: {result.stderr[:400]}")
        return [], None

    raw_rows = []
    for line in result.stdout.splitlines():
        if line.startswith("label,"):
            continue                              # header
        try:
            lab, it, us, *cy = line.split(",")
            raw_rows.append({
                "label": lab,
                "iteration": int(it),
                "latency_ms": float(us) / 1000.0,
                "cycles": int(cy[0]) if cy else 0,   # 0 = no cycle counter (not Linux, or perf not allowed)
            })
        except (ValueError, IndexError):
            pass

    # Parse metadata from stderr "#meta label=... pk=... sk=... sig=..."
    meta = None
    m = re.search(r"#meta label=\S+ pk=(\d+) sk=(\d+) sig=(\d+)", result.stderr)
    if m:
        meta = {
            "label": label,
            "pk_bytes": int(m.group(1)),
            "sk_bytes": int(m.group(2)),
            "sig_bytes": int(m.group(3)),
        }
    return raw_rows, meta


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def percentile(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = max(0, min(len(xs) - 1, int(round(p * (len(xs) - 1)))))
    return xs[k]


def summary_rows_from_raw(raw_rows: list[dict]) -> list[dict]:
    """Aggregate per-iteration latencies into one summary row per label."""
    by_label: dict[str, list[float]] = {}
    cycles: dict[str, list[int]] = {}
    for r in raw_rows:
        by_label.setdefault(r["label"], []).append(r["latency_ms"])
        cycles.setdefault(r["label"], []).append(r.get("cycles", 0))
    out = []
    for label, samples in by_label.items():
        if not samples:
            continue
        cy = cycles[label]
        out.append({
            "label":   label,
            "n":       len(samples),
            "mean_ms": statistics.mean(samples),
            "stdev_ms": statistics.stdev(samples) if len(samples) > 1 else 0.0,
            "p50_ms":  percentile(samples, 0.50),
            "p90_ms":  percentile(samples, 0.90),
            "p99_ms":  percentile(samples, 0.99),
            "min_ms":  min(samples),
            "max_ms":  max(samples),
            "mean_cycles": round(statistics.mean(cy)) if any(cy) else "",
            "median_cycles": round(statistics.median(cy)) if any(cy) else "",
        })
    return out


# ---------------------------------------------------------------------------
# CSV writers (upsert-style)
# ---------------------------------------------------------------------------

def upsert_summary(path: Path, new_rows: list[dict]) -> None:
    keep = {}
    if path.exists():
        with path.open() as f:
            for row in csv.DictReader(f):
                keep[row["label"]] = row
    for r in new_rows:
        keep[r["label"]] = {k: str(v) for k, v in r.items()}
    rows = list(keep.values())
    if not rows:
        return
    with path.open("w", newline="") as f:  # union of columns: rows from parse_native_output.py carry no cycles
        w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for r in rows for k in r)), restval="")
        w.writeheader()
        w.writerows(rows)


def upsert_meta(path: Path, new_meta: list[dict]) -> None:
    keep = {}
    if path.exists():
        with path.open() as f:
            for row in csv.DictReader(f):
                keep[row["friendly_name"]] = row
    for m in new_meta:
        keep[m["friendly_name"]] = {k: str(v) for k, v in m.items()}
    rows = list(keep.values())
    if not rows:
        return
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def append_raw(path: Path, new_rows: list[dict]) -> None:
    if not new_rows:
        return
    old = list(csv.DictReader(path.open())) if path.exists() else []  # rewritten: older files have no cycles column
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["label", "iteration", "latency_ms", "cycles"], restval="")
        w.writeheader()
        w.writerows(old + new_rows)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--iterations", type=int, default=200,
                    help="iterations per variant (run_all.sh: SIG_N, the same for every algorithm)")
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--results-dir", default=str(DEFAULT_RESULTS))
    ap.add_argument("--algos", nargs="*", default=None,
                    help="Restrict to specific top-level algo families "
                         "(SDitH, QR-UOV, FAEST)")
    ap.add_argument("--variants", nargs="*", default=None,
                    help="Restrict to specific variants by friendly name")
    ap.add_argument("--quick", action="store_true",
                    help="Cap iterations to 20 for everything (smoke test)")
    ap.add_argument("--probe-only", action="store_true",
                    help="Build only, run a 1-iter pass to capture pk/sig/sk "
                         "sizes; skip timing benchmarks. Writes only meta CSV.")
    ap.add_argument("--verbose", action="store_true",
                    help="Print full build commands")
    args = ap.parse_args()

    compiler = _find_compiler()
    print(f"[+] compiler: {compiler}")
    print(f"[+] bench template: {BENCH_C}")

    with ALGOS_JSON.open() as f:
        algos = json.load(f)
    algos = {k: v for k, v in algos.items() if not k.startswith("_")}

    # Filter
    if args.algos:
        algos = {k: v for k, v in algos.items() if k in args.algos}
    if not algos:
        sys.exit("[-] no algorithms match --algos filter")

    # Resolve variant dirs (each is relative to reference/<root_dir>/)
    work_list = []
    for algo_name, cfg in algos.items():
        root = HERE / _cache(cfg["root_dir"])
        strategy = cfg.get("build_strategy", "generic-bench")
        if not root.is_dir():
            github = cfg.get("github", "(no github URL)")
            print(f"[!] {algo_name}: directory missing -- "
                  f"clone it from {github}")
            continue
        variants = cfg.get("variants", [])
        if not variants:
            print(f"[!] {algo_name}: no variants in algos.json "
                  f"(strategy={strategy}; see README.md)")
            continue
        for v in variants:
            v["_build_strategy"] = strategy
            if "dir" in v:
                v["_resolved_dir"] = Path(_cache(cfg["root_dir"])) / v["dir"]
            if args.variants and v["name"] not in args.variants:
                continue
            work_list.append((algo_name, v))

    if not work_list:
        sys.exit("[-] no variants to build (download algorithm sources first)")

    print(f"[+] will attempt {len(work_list)} variants "
          f"across {len(set(a for a, _ in work_list))} algorithms")

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    summary_path = results_dir / "sig_summary_reference.csv"
    raw_path     = results_dir / "sig_raw_reference.csv"
    meta_path    = results_dir / "sig_meta_reference.csv"

    new_summary_rows = []
    new_raw_rows     = []
    new_meta_rows    = []

    for algo_name, v in work_list:
        name = v["name"]
        print(f"\n[+] {algo_name} :: {name}")
        exe = build_variant(algo_name, v, compiler=compiler, verbose=args.verbose)
        if exe is None:
            continue

        # Probe-only pass: just run one iteration to get sizes from stderr.
        if args.probe_only:
            _, meta = run_variant(exe, name, iters=1, warmup=0, timeout_s=120)
            if meta:
                new_meta_rows.append({
                    "friendly_name": name,
                    "family":        f"ref-{algo_name.lower()}",
                    "status":        "Onramp R2",
                    "nist_level":    0,
                    "pk_bytes":      meta["pk_bytes"],
                    "sk_bytes":      meta["sk_bytes"],
                    "sig_bytes":     meta["sig_bytes"],
                })
                print(f"    pk={meta['pk_bytes']} sk={meta['sk_bytes']} sig={meta['sig_bytes']}")
            continue

        iters = min(20, args.iterations) if args.quick else args.iterations
        print(f"    n={iters} (warmup={args.warmup})")

        t0 = time.perf_counter()
        raw, meta = run_variant(exe, name, iters=iters, warmup=args.warmup)
        wall = time.perf_counter() - t0
        if not raw:
            continue

        summary = summary_rows_from_raw(raw)
        new_summary_rows.extend(summary)
        new_raw_rows.extend(raw)
        if meta:
            new_meta_rows.append({
                "friendly_name": name,
                "family":        f"ref-{algo_name.lower()}",
                "status":        "Onramp R2",
                "nist_level":    0,
                "pk_bytes":      meta["pk_bytes"],
                "sk_bytes":      meta["sk_bytes"],
                "sig_bytes":     meta["sig_bytes"],
            })
        for r in summary:
            print(f"    {r['label']:40s} n={r['n']:3d}  "
                  f"p50={r['p50_ms']:9.3f} ms  p90={r['p90_ms']:9.3f} ms mean={r['mean_ms']:9.3f} ms")
        print(f"    [{wall:6.1f}s]")

    if new_summary_rows:
        upsert_summary(summary_path, new_summary_rows)
        print(f"\n[+] Wrote {summary_path} (+{len(new_summary_rows)} rows)")
    if new_raw_rows:
        append_raw(raw_path, new_raw_rows)
        print(f"[+] Wrote {raw_path} (+{len(new_raw_rows)} samples)")
    if new_meta_rows:
        upsert_meta(meta_path, new_meta_rows)
        print(f"[+] Wrote {meta_path} (+{len(new_meta_rows)} variants)")



if __name__ == "__main__":
    main()
