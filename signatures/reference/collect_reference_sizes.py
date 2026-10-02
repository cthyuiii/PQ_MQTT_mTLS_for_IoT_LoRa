#!/usr/bin/env python3
"""Collect pk / sk / sig sizes for the native-bench reference signature algos
and upsert them into results/sig_meta_reference.csv (the CSV the workbook reads).

Sources (no benchmark re-run needed except MQOM):
  HAWK    : HAWK/NIST/Reference_Implementation/hawk{256,512,1024}/api.h  (literal)
  FAEST   : FAEST/build_release/<variant>/api.h                          (literal)
  SQIsign : SQIsign/src/nistapi/lvl{1,3,5}/api.h                         (literal)
  MQOM    : MQOM/mqom_results.txt  (the "Communication cost" lines; run its
            bench first - sizes are macro-computed, not in a literal api.h)
  SDitH   : already populated by run_reference_benchmarks.py (left as-is)

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


def faest_friendly(name):
    f = name.upper().replace("_", "-")
    return re.sub(r"-(\d+)([FS])$", lambda m: f"-{m.group(1)}{m.group(2).lower()}", f)


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

    # FAEST (12 standard variants)
    bdir = HERE / "FAEST/build_release"
    if bdir.exists():
        for d in sorted(bdir.glob("faest_*")):
            if re.fullmatch(r"faest_(em_)?(128|192|256)[sf]", d.name) and (d / "api.h").exists():
                add(faest_friendly(d.name), "ref-faest", "Onramp R2",
                    level_from(d.name), read_apih(d / "api.h"))

    # SQIsign
    for lvl, roman in ((1, "I"), (3, "III"), (5, "V")):
        add(f"SQIsign-NIST-{roman}", "ref-sqisign", "Onramp R2", lvl,
            read_apih(HERE / f"SQIsign/src/nistapi/lvl{lvl}/api.h"))

    # MQOM - from its bench output's "Communication cost" section
    mqom_txt = HERE / "MQOM/mqom_results.txt"
    if mqom_txt.exists():
        cur = pk = sk = sig = None
        for line in mqom_txt.read_text().splitlines():
            m = re.match(r"=== (\S+) ===", line)
            if m:
                cur, pk, sk, sig = m.group(1), None, None, None
                continue
            if cur is None:
                continue
            if (mm := re.match(r"\s*-\s*PK size:\s*(\d+)", line)):            pk = int(mm.group(1))
            elif (mm := re.match(r"\s*-\s*SK size:\s*(\d+)", line)):          sk = int(mm.group(1))
            elif (mm := re.match(r"\s*-\s*Signature size:\s*(\d+)", line)):   sig = int(mm.group(1))
            if None not in (pk, sk, sig):
                parts = cur.replace("_r3", "").replace("_r5", "").split("_")
                add("MQOM-" + "-".join(parts), "ref-mqom", "Onramp R2",
                    level_from(cur), (pk, sk, sig))
                pk = sk = sig = None
    else:
        print(f"[i] {mqom_txt.name} not found - skipping MQOM (run its bench first).")

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
