"""Merge Stage 1 signature results from the Pi into the customer's table form.

Same columns as pico/logs/results.csv (the form the customer presented),
plus a trailing Library column, so Pi and Pico rows stack in one sheet:

  Board,Algorithm,pk,sk,sigMax,sig,
  {keygen,sign,verify}_{mean_us,median_us,std_us,mean_cyc,median_cyc,ops_s},status,Library

Inputs (any subset):
  --sig-speed CSV META LIB
                            sig_speed.c output (OpenSSL, liboqs or wolfSSL build) + its stderr (#meta lines)
  --summary CSV META LIB    percentile-schema results: NIST reference (sig_*_reference.csv)

  python signatures/to_customer_form.py --board pi5 --out results/pi_stage1_pi5.csv \\
      --sig-speed results/openssl_sig_speed_pi.csv results/openssl_sig_speed_pi.meta "OpenSSL 3.5.1" \\
      --sig-speed results/wolfssl_sig_speed_pi.csv results/wolfssl_sig_speed_pi.meta "wolfSSL 5.9.4"
  python signatures/to_customer_form.py --selftest
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

OPS = ("keygen", "sign", "verify")
STATS = ("mean_us", "median_us", "std_us", "min_us", "max_us", "mean_cyc", "median_cyc", "ops_s")
COLS = ["Board", "Algorithm", "pk", "sk", "sigMax", "sig",
        *[f"{op}_{s}" for op in OPS for s in STATS], "status", "Library"]


def pretty(name: str) -> str:
    """OpenSSL / oqsprovider / liboqs spellings -> the Pico table's."""
    fixed = {"RSA:2048": "RSA-2048", "RSA:3072": "RSA-3072", "EC:P-256": "ECDSA-P256",
             "ED25519": "Ed25519", "ED448": "Ed448"}
    if name in fixed:
        return fixed[name]
    if m := re.fullmatch(r"(falcon|mayo)(\d+)", name, re.I):
        return f"{'Falcon' if m[1].lower() == 'falcon' else 'MAYO'}-{m[2]}"
    if m := re.fullmatch(r"snova(\d{2})(\d{1,2})(\d)", name, re.I):
        return f"SNOVA-{m[1]}-{m[2]}-{m[3]}"
    if m := re.fullmatch(r"SLH_DSA_PURE_(SHA2|SHAKE)_(\d+)([FS])", name):  # liboqs
        return f"SLH-DSA-{m[1]}-{m[2]}{m[3].lower()}"
    if m := re.fullmatch(r"SNOVA_(\d+)_(\d+)_(\d+)(\w*)", name):  # liboqs: SNOVA_24_5_4_SHAKE_esk
        return f"SNOVA-{m[1]}-{m[2]}-{m[3]}" + m[4].replace("_", "-")
    if m := re.fullmatch(r"OV-(\S+)", name):  # liboqs UOV
        return "UOV-" + m[1]
    if m := re.fullmatch(r"snova([135])([bks])", name, re.I):  # round 3 (oqs-provider 36cafae), liboqs spelling
        return f"SNOVA_{dict(zip('135', ('I', 'III', 'V')))[m[1]]}_{m[2].upper()}"
    if m := re.fullmatch(r"mqom(\d)(cat\d)(gf\d+)(fast|short|shorter)(ct|ot|r\d)", name, re.I):
        return "_".join(("mqom" + m[1], *m.groups()[1:]))
    return name


def status_of(row: dict) -> str:
    return "OK" if all(f"{op}_mean_us" in row for op in OPS) else "PARTIAL"


def from_openssl(csv_path: Path, meta_path: Path, lib: str, board: str) -> list[dict]:
    meta = {}
    for line in meta_path.read_text().splitlines():
        if line.startswith("#meta "):
            kv = dict(x.split("=", 1) for x in line[6:].split())
            meta.setdefault(kv.pop("algo"), {}).update(kv)
    rows = {}
    with csv_path.open() as f:
        for r in csv.DictReader(f):
            op, mean = r["op"], float(r["mean_ms"]) * 1e3
            us = lambda k: float(r[k]) * 1e3 if r.get(k) else ""  # older files lack min / max
            rows.setdefault(r["algo"], {}).update({
                f"{op}_mean_us": mean, f"{op}_ops_s": 1e6 / mean if mean else "",
                f"{op}_median_us": us("median_ms"), f"{op}_std_us": us("std_ms"),
                f"{op}_min_us": us("min_ms"), f"{op}_max_us": us("max_ms"),
                f"{op}_mean_cyc": int(r["mean_cycles"]) or "",  # 0 = no cycle counter
                f"{op}_median_cyc": int(r.get("median_cycles") or 0) or ""})
    out = []
    for algo in dict.fromkeys([*meta, *rows]):
        m, r = meta.get(algo, {}), rows.get(algo, {})
        out.append(dict(Board=board, Algorithm=pretty(algo), pk=m.get("pk", ""), sk=m.get("sk", ""),
                        sigMax=m.get("sigmax", ""), sig=m.get("sig", ""), **r,
                        status=m.get("status") or status_of(r), Library=lib))
    return out


def from_summary(summary: Path, meta: Path, lib: str, board: str) -> list[dict]:
    with meta.open() as f:
        sizes = {r["friendly_name"]: r for r in csv.DictReader(f)}
    rows = {}
    with summary.open() as f:
        for r in csv.DictReader(f):
            algo, _, op = r["label"].rpartition(" ")
            if op in OPS:
                mean = float(r["mean_ms"]) * 1e3
                rows.setdefault(algo, {}).update({
                    f"{op}_mean_us": mean, f"{op}_median_us": float(r["p50_ms"]) * 1e3,
                    f"{op}_std_us": float(r["stdev_ms"]) * 1e3, f"{op}_ops_s": 1e6 / mean if mean else "",
                    f"{op}_min_us": float(r["min_ms"]) * 1e3 if r.get("min_ms") else "",
                    f"{op}_max_us": float(r["max_ms"]) * 1e3 if r.get("max_ms") else "",
                    f"{op}_mean_cyc": r.get("mean_cycles") or "", f"{op}_median_cyc": r.get("median_cycles") or ""})
    return [dict(Board=board, Algorithm=a, pk=sizes.get(a, {}).get("pk_bytes", ""),
                 sk=sizes.get(a, {}).get("sk_bytes", ""), sigMax=sizes.get(a, {}).get("sig_bytes", ""),
                 sig=sizes.get(a, {}).get("sig_bytes", ""), **r, status=status_of(r), Library=lib)
            for a, r in rows.items()]


def selftest():
    assert pretty("falcon512") == "Falcon-512" and pretty("mayo3") == "MAYO-3"
    assert pretty("snova2454") == "SNOVA-24-5-4" and pretty("snova37172") == "SNOVA-37-17-2"
    assert pretty("snova1b") == "SNOVA_I_B" and pretty("snova5s") == "SNOVA_V_S"
    assert pretty("mqom3cat1gf16fastct") == "mqom3_cat1_gf16_fast_ct"
    assert pretty("SLH_DSA_PURE_SHA2_128S") == "SLH-DSA-SHA2-128s" and pretty("OV-Ip-pkc") == "UOV-Ip-pkc"
    assert pretty("SNOVA_24_5_4_SHAKE_esk") == "SNOVA-24-5-4-SHAKE-esk" and pretty("SNOVA_29_6_5") == "SNOVA-29-6-5"
    assert pretty("Falcon-padded-512") == "Falcon-padded-512"
    assert pretty("EC:P-256") == "ECDSA-P256" and pretty("ML-DSA-44") == "ML-DSA-44"
    print("to_customer_form self-check OK")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--board", default="pi")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--sig-speed", nargs=3, action="append", default=[], metavar=("CSV", "META", "LIBRARY"))
    ap.add_argument("--summary", nargs=3, action="append", default=[], metavar=("CSV", "META", "LIBRARY"))
    ap.add_argument("--match", default="", help="comma list: keep only matching algorithms (run_all.sh --algo)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.out:
        ap.error("--out is required")

    rows = []
    for c, m, lib in args.sig_speed:  # OpenSSL (pinned provider), OpenSSL (round 3 provider), liboqs, wolfSSL
        rows += from_openssl(Path(c), Path(m), lib, args.board)
    for c, m, lib in args.summary:
        rows += from_summary(Path(c), Path(m), lib, args.board)
    if args.match:  # same rule as run_all.sh --algo: case/punctuation-insensitive substring
        norm = lambda t: re.sub(r"[^a-z0-9]", "", t.lower())
        want = [norm(m) for m in args.match.split(",")]
        rows = [r for r in rows if any(w in norm(r["Algorithm"]) for w in want)]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows({k: round(v, 3) if isinstance(v, float) else v for k, v in r.items()} for r in rows)
    print(f"[+] wrote {args.out}  ({len(rows)} rows, {sum(r['status'] == 'OK' for r in rows)} OK)")


if __name__ == "__main__":
    main()
