#!/usr/bin/env python3
"""collate_results.py - every result this repo produces, in one long CSV: results/all_results.csv.

One row per number:
  platform,run,stage,library,algorithm,mode,group,payload_scheme,payload_B,operation,metric,value,unit,n,status,source
  platform  the machine (Darwin-arm64, pi4, rp2040, qemu-cortex-m33, ...); run = the file's tag (mac, pi, ...)
  status    OK, or why a combination failed (failures are results); failed rows carry no value
Reads results/*_<tag>.* and pico/logs/. Skips *_quick* (smoke runs) and untagged legacy files.
Only signatures (Stage 1, Pico signature sketches, QEMU counts) are measured on one machine. Everything else goes
through an MQTT broker on another machine and counts only then (meta: broker_local false): Stage 2, the TLS
key-exchange sweep, the KEM exchange as MQTT messages, and the pipeline's LoRaWAN / AES / Ascon messages.
run_all.sh calls it at the end; run it again after a Pico run:   python3 scripts/collate_results.py
"""
import csv
import glob
import json
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES, PICO = ROOT / "results", ROOT / "pico" / "logs"
COLS = ["platform", "run", "stage", "library", "algorithm", "mode", "group", "payload_scheme", "payload_B",
        "operation", "metric", "value", "unit", "n", "status", "source"]
rows = []
not_counted = []  # MQTT runs with the broker on the same machine


HS_OPS = (("hs_keygen", "handshake: key share (client)"), ("hs_derive", "handshake: key share completion (client)"),
          ("hs_verify", "handshake: verify (client)"), ("hs_sign", "handshake: sign (client)"))


def emit(value, **kw):
    """one number (skipped when empty); kw fills the other columns"""
    if value in (None, "") and kw.get("status", "OK") == "OK":
        return
    rows.append({c: kw.get(c, "") for c in COLS} | {"value": value if value is not None else ""})


def tagged(pattern):
    """(path, run) for results/<stem>_<tag>.<ext>, without smoke runs. A file older than its run's
    versions_<tag>.json (or with none) is an earlier run: run = "<tag> (<date>, versions not recorded)"."""
    stem, ext = pattern.split("*")
    for p in sorted(glob.glob(str(RES / pattern))):
        tag = os.path.basename(p)[len(stem):-len(ext)]
        if not tag or "quick" in tag:
            continue
        vp = RES / f"versions_{tag}.json"
        mtime = os.path.getmtime(p)
        if not vp.exists() or mtime < os.path.getmtime(vp) - 2 * 86400:
            tag = f"{tag} ({time.strftime('%Y-%m-%d', time.localtime(mtime))}, versions not recorded)"
        yield Path(p), tag


def versions(run):
    """versions_<tag>.json of a current run ({} for an earlier, unrecorded one)"""
    p = RES / f"versions_{run.split(' ')[0]}.json"
    return json.loads(p.read_text()) if p.exists() and " " not in run else {}


def plat(run):
    """the board versions_<tag>.json names (Darwin-arm64, pi4, ...), else the tag"""
    return versions(run).get("board") or run.split(" ")[0]


def csv_rows(p):
    with open(p, newline="") as f:
        return list(csv.DictReader(f))


def signatures(p, run, stage, default_platform):
    """the customer's Pico form (Stage 1 table, pico results.csv): sizes + keygen/sign/verify stats"""
    for r in csv_rows(p):
        base = dict(platform=r.get("Board") or default_platform, run=run, stage=stage, library=r.get("Library", ""),
                    algorithm=r["Algorithm"], status=r.get("status") or "OK", source=p.name)
        if base["status"] != "OK" and not any(r.get(f"{op}_mean_us") for op in ("keygen", "sign", "verify")):
            emit("", **base, operation="status")
            continue
        for k in ("pk", "sk", "sigMax", "sig"):
            emit(r.get(k), **base, operation="size", metric=f"{k}_B", unit="B")
        for op in ("keygen", "sign", "verify"):
            for m, unit in (("mean_us", "us"), ("median_us", "us"), ("std_us", "us"), ("min_us", "us"),
                            ("max_us", "us"), ("mean_cyc", "cycles"),
                            ("median_cyc", "cycles"), ("ops_s", "ops/s")):
                emit(r.get(f"{op}_{m}"), **base, operation=op, metric=m.replace("_us", "").replace("_cyc", "_cycles"),
                     unit=unit)


# ---- Stage 1 signatures (OpenSSL, liboqs, wolfSSL, reference: one table per run) + Pico
for p, tag in tagged("stage1_customer_form_*.csv"):
    signatures(p, tag, "Stage 1 signatures", plat(tag))
if (PICO / "results.csv").exists():
    signatures(PICO / "results.csv", "pico", "Pico signatures", "")

# ---- TLS / mTLS key-exchange sweep: MQTT connections through the broker; only two-machine runs count
for p, tag in tagged("tls_handshake_pure_*.csv"):
    meta_p = RES / f"tls_handshake_meta_{tag.split(' ')[0]}.json"
    meta = json.loads(meta_p.read_text()) if meta_p.exists() else {}
    if meta.get("broker_local", True):  # no meta, or the broker on this machine: not counted
        not_counted.append(p.name)
        continue
    v = versions(tag)  # the Pico's sweep (tag pico_<board>) is wolfSSL's
    lib = v.get("openssl_cli") or (f"wolfSSL {v['wolfssl']}" if v.get("wolfssl") else "OpenSSL (version not recorded)")
    for r in csv_rows(p):
        base = dict(platform=plat(tag), run=tag, stage="TLS handshake", library=lib, algorithm=r["sig"],
                    mode=r["mode"], group=r["group"], operation="handshake", n=r["n"], status=r.get("status") or "OK",
                    source=p.name)
        if base["status"] != "OK":
            emit("", **base)
            continue
        for m in ("mean_ms", "median_ms", "p50_ms", "std_ms", "min_ms", "max_ms", "p90_ms", "p99_ms"):  # p50: older files
            emit(r.get(m), **base, metric=m[:-3].replace("p50", "median"), unit="ms")
        emit(r.get("ops_s"), **base, metric="handshakes_per_s", unit="1/s")
        for k in ("hs_tx_B", "hs_rx_B", "hs_B", "wire_tx_B", "wire_rx_B", "wire_B"):
            emit(r.get(k), **(base | dict(operation="bytes")), metric=k[:-2], unit="B")
        for k in ("writes", "reads", "tx_segs", "rx_segs"):
            emit(r.get(k), **(base | dict(operation="socket / TCP")), metric=k, unit="count")
        for k, opname in HS_OPS:  # the client's crypto inside the handshake (hs_timing.c), when timed
            if r.get(f"{k}_median_us") not in (None, ""):
                emit(r[f"{k}_median_us"], **(base | dict(operation=opname)), metric="median", unit="us")
                emit(r.get(f"{k}_n"), **(base | dict(operation=opname)), metric="calls", unit="count")

# ---- Stage 2 (MQTT over plain / TLS / mTLS) and the full pipeline
for stem, stage in (("mqtt_mtls_summary_", "Stage 2 MQTT connect"), ("pipeline_summary_", "Pipeline")):
    for p, tag in tagged(stem + "*.csv"):
        meta_p = RES / f"{stem.replace('summary_', 'meta_')}{tag.split(' ')[0]}.json"
        meta = json.loads(meta_p.read_text()) if meta_p.exists() else {}
        host = meta.get("broker", "").rpartition(":")[0]
        if meta.get("role") != "client" or meta.get("broker_local", host in ("127.0.0.1", "localhost", "::1")):
            not_counted.append(p.name)
            continue
        payload = meta.get("payload_B", "") if stage == "Pipeline" else ""
        for r in csv_rows(p):
            lib = r["Library"] if r["Library"] == "none" else f"{r['Library']} ({r.get('library_version') or ''})"
            base = dict(platform=r["Board"], run=tag, stage=stage, library=lib, algorithm=r["Signature"],
                        mode=r["Mode"], group=r["Group"],  # pipeline: scheme + frame direction, e.g. "ascon downlink"
                        payload_scheme=" ".join(x for x in (r.get("AEAD", ""), r.get("Direction", "")) if x),
                        payload_B=payload if r.get("AEAD") else "", n=r.get("n", ""), status=r["status"] or "OK",
                        source=p.name)
            if base["status"] != "OK":  # PARTIAL (a Pico block cut off by a hang) keeps its numbers
                emit("", **base, operation="status")
                if not base["status"].startswith("PARTIAL"):
                    continue
            for op in ("tcp", "tls", "mqtt", "total"):
                for s in ("mean", "median", "std", "min", "max"):
                    emit(r.get(f"{op}_{s}_ms"), **base, operation=f"{op} connect" if op != "total" else "connect total",
                         metric=s, unit="ms")
            for k in ("hs_tx_B", "hs_rx_B", "mqtt_tx_B", "mqtt_rx_B", "total_tx_B", "total_rx_B", "total_B",
                      "wire_tx_B", "wire_rx_B", "wire_B", "server_cert_B", "client_cert_B"):
                emit(r.get(k), **base, operation="bytes", metric=k[:-2], unit="B")
            for k in ("hs_writes", "hs_reads", "writes", "reads", "tx_segs", "rx_segs"):
                emit(r.get(k), **base, operation="socket / TCP", metric=k, unit="count")
            for k in ("peak_heap_B", "stack_peak_B", "free_heap_first_B", "free_heap_last_B"):  # Pico: wolfSSL's
                emit(r.get(k), **base, operation="memory", metric=k[:-2], unit="B")  # peak heap, peak stack, free heap
            for k, opname in HS_OPS:  # the client's crypto inside the handshake (hs_timing.c), when timed
                if r.get(f"{k}_median_us") not in (None, ""):
                    for s in ("mean", "median", "std", "min", "max"):
                        emit(r.get(f"{k}_{s}_us"), **base, operation=opname, metric=s, unit="us")
                    emit(r.get(f"{k}_n"), **base, operation=opname, metric="calls", unit="count")
            if stage == "Pipeline":
                msg = base | dict(n=r.get("msgs", ""))
                for key, opname, unit in (("seal", "seal", "us"), ("open", "open", "us"),
                                          ("rtt", "broker round trip", "ms"), ("e2e", "end to end", "ms")):
                    for s in ("mean", "median", "std", "min", "max", "p90"):
                        emit(r.get(f"{key}_{s}_{unit}"), **msg, operation=opname, metric=s, unit=unit)
                emit(r.get("msg_tx_B"), **msg, operation="bytes per message", metric="tx", unit="B")
                emit(r.get("msg_rx_B"), **msg, operation="bytes per message", metric="rx", unit="B")

# ---- KEM exchange as MQTT messages through the broker (Classic McEliece, HQC, ML-KEM); two-machine runs only
for p, tag in tagged("kem_exchange_summary_*.csv"):
    meta_p = RES / f"kem_exchange_meta_{tag.split(' ')[0]}.json"
    meta = json.loads(meta_p.read_text()) if meta_p.exists() else {}
    if meta.get("broker_local", True):
        not_counted.append(p.name)
        continue
    for r in csv_rows(p):
        base = dict(platform=r["Board"], run=tag, stage="KEM exchange (MQTT)", library=r.get("library_version", ""),
                    algorithm=r["KEM"], n=r.get("n", ""), status=r["status"] or "OK", source=p.name)
        if base["status"] != "OK":
            emit("", **base, operation="status")
            if not base["status"].startswith("PARTIAL"):
                continue
        for op, opname, unit in (("keygen", "keygen (client)", "us"), ("encaps", "encapsulate (responder)", "us"),
                                 ("decaps", "decapsulate (client)", "us"), ("rtt", "broker round trip", "ms"),
                                 ("total", "exchange total", "ms")):
            for st in ("mean", "median", "std", "min", "max", "p90"):
                emit(r.get(f"{op}_{st}_{unit}"), **base, operation=opname, metric=st, unit=unit)
        for k in ("pk_B", "ct_B", "ss_B", "tx_B", "rx_B"):
            emit(r.get(k), **base, operation="bytes", metric=k[:-2], unit="B")

# ---- Pico liboqs Keccak swap, counted in QEMU
q = PICO / "qemu_liboqs_keccak.csv"
if q.exists():
    for r in csv_rows(q):
        base = dict(platform=f"qemu-{r['cpu']}", run="qemu", stage="Pico liboqs Keccak variants (QEMU)",
                    library=f"liboqs 0.16.0, Keccak {r['keccak']}", algorithm=r["algorithm"],
                    status="OK" if r["known_answers"] == "OK" and r["same_output"] == "True" else "FAILED checks",
                    source=q.name)
        for op in ("keygen", "sign", "verify"):
            emit(r[f"{op}_insns"], **base, operation=op, metric="instructions", unit="instructions")
            emit(r[f"speedup_{op}"], **base, operation=op, metric="speedup_vs_plain64", unit="x")

bad = [r for r in rows if not r["stage"] or not r["algorithm"] or (r["status"] == "OK" and r["value"] == "")]
assert not bad, f"{len(bad)} rows without a stage, algorithm or value, e.g. {bad[:2]}"
out = RES / "all_results.csv"
with open(out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=COLS)
    w.writeheader()
    w.writerows(rows)
print(f"[+] wrote {out}  ({len(rows)} rows from {len({r['source'] for r in rows})} files)")
if not_counted:
    print(f"[i] not counted (server on the same machine as the client): {', '.join(not_counted)}")
