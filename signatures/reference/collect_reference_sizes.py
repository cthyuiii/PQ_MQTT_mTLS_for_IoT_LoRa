#!/usr/bin/env python3
"""Collect pk / sk / sig sizes for the native-bench reference signature algos
and upsert them into results/sig_meta_reference.csv (the CSV the workbook reads).

Sources:
  HAWK    : HAWK/NIST/Reference_Implementation/hawk{256,512,1024}/api.h  (literal)
  SDitH, FAEST, SQIsign, QR-UOV: their round 3 sizes come from run_reference_benchmarks.py (left as-is);
  MQOM: liboqs (run_all.sh round3 stage)

Usage:
    python collect_reference_sizes.py                 # writes results/sig_meta_reference.csv
    python collect_reference_sizes.py --meta /tmp/x.csv   # write elsewhere (testing)
"""
import argparse, csv, re
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIELDS = ["friendly_name", "family", "status", "nist_level",
          "pk_bytes", "sk_bytes", "sig_bytes"]


def read_apih(path):
    """(pk, sk, sig) from a literal api.h, or None if any value is non-literal."""
    try:
        txt = Path(path).read_text()
    except OSError:
        return None
    def g(name):
        m = re.search(rf"#define\s+{name}\s+(\d+)\b", txt)
        return int(m.group(1)) if m else None
    pk, sk, sig = g("CRYPTO_PUBLICKEYBYTES"), g("CRYPTO_SECRETKEYBYTES"), g("CRYPTO_BYTES")
    return None if None in (pk, sk, sig) else (pk, sk, sig)


def level_from(token):
    return 1 if ("128" in token or "cat1" in token or "lvl1" in token) else \
           3 if ("192" in token or "cat3" in token or "lvl3" in token) else 5


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--meta", type=Path,
                    default=HERE.parent.parent / "results" / "sig_meta_reference.csv")
    args = ap.parse_args()

    rows = {}
    def add(friendly, family, status, level, sizes):
        if sizes:
            pk, sk, sig = sizes
            rows[friendly] = dict(friendly_name=friendly, family=family, status=status,
                                  nist_level=level, pk_bytes=pk, sk_bytes=sk, sig_bytes=sig)

    # HAWK
    for deg in ("256", "512", "1024"):
        add(f"HAWK-{deg}", "ref-hawk", "Onramp R1", level_from(deg),
            read_apih(HERE / f"HAWK/NIST/Reference_Implementation/hawk{deg}/api.h"))

    # upsert (preserve existing rows e.g. SDitH)
    keep = {}
    if args.meta.exists():
        with args.meta.open() as f:
            for r in csv.DictReader(f):
                keep[r["friendly_name"]] = r
    keep.update({k: {fn: str(v.get(fn, "")) for fn in FIELDS} for k, v in rows.items()})
    args.meta.parent.mkdir(parents=True, exist_ok=True)
    with args.meta.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in keep.values():
            w.writerow({fn: r.get(fn, "") for fn in FIELDS})

    print(f"[+] upserted {len(rows)} reference-size rows into {args.meta}")
    for k in sorted(rows):
        r = rows[k]
        print(f"    {k:28s} pk={r['pk_bytes']:>7} sk={r['sk_bytes']:>7} sig={r['sig_bytes']:>7}")


if __name__ == "__main__":
    main()
