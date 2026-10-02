#!/usr/bin/env python3
"""mqtt_tls_bench's serial output -> run_benchmarks.save_mqtt -> collate_results.py, on a made-up transcript,
in a scratch copy (the real results/ is not touched). Run: python3 pico/tests/mqtt_parse_test.py"""
import csv, os, subprocess, sys, tempfile
from pathlib import Path

PICO = Path(__file__).resolve().parents[1]
ROOT = PICO.parent
sys.path[:0] = [str(PICO), str(ROOT / "network")]
import run_benchmarks as r

TXT = """=== MQTT / TLS 1.3 / mTLS, MLDSA44 certificates, X25519MLKEM768 (wolfSSL 5.9.4) on RP2040 ===
#config iterations=2 warmup=1 pipe_iterations=1 messages=2 payload_B=51 schemes=6 sweep_iterations=2 sweep_warmup=1 groups=13
#wifi rssi=-51 dBm channel=6 ip=192.168.1.9 broker=192.168.1.2
#block connect plain
#lib none (plain MQTT)
iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B,hs_writes,hs_reads,writes,reads
0,4.0,0.0,3.0,7.0,0,0,23,4,0,0,1,1
1,6.0,0.0,5.0,11.0,0,0,23,4,0,0,1,1
#end
#block connect mTLS
#suite TLS13-AES256-GCM-SHA384
#lib wolfSSL 5.9.4
iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B,hs_writes,hs_reads,writes,reads,free_heap_B,hs_keygen_us,hs_derive_us,hs_verify_us,hs_sign_us,hs_keygen_n,hs_derive_n,hs_verify_n,hs_sign_n
0,4.0,300.0,3.0,307.0,6000,6500,45,300,4,9,5,12,150000,90000.0,85000.0,54000.0,208000.0,2,2,2,1
1,4.0,310.0,3.0,317.0,6000,6500,45,300,4,9,5,12,149000,92000.0,87000.0,54000.0,210000.0,2,2,2,1
#heap 61000
#end
#block connect TLS
#lib wolfSSL 5.9.4
iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B,hs_writes,hs_reads,writes,reads
#err tls handshake failed: made-up failure
#heap 20000
#end
#block pipeline mTLS lorawan11 up
#aead LoRaWAN-1.1 AES-128-CTR+2xCMAC (BearSSL (arduino-pico)), uplink, 51 B payload + 13 B overhead
#lib wolfSSL 5.9.4
iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B,hs_writes,hs_reads,writes,reads
msg,iter,idx,seal_us,rtt_us,open_us,tx_B,rx_B
0,4.0,300.0,3.0,307.0,6000,6500,45,300,4,9,5,12
msg,0,0,3,9000,2,101,101
msg,0,1,3,11000,2,101,101
#heap 62000
#end
#block pipeline TLS ascon down
#lib wolfSSL 5.9.4
iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B,hs_writes,hs_reads,writes,reads,free_heap_B
msg,iter,idx,seal_us,rtt_us,open_us,tx_B,rx_B
0,4.0,300.0,3.0,307.0,6000,6500,45,300,4,9,5,12,90000
msg,0,0,3,8000,2,101,101
=== MQTT / TLS 1.3 / mTLS, MLDSA44 certificates, X25519MLKEM768 (wolfSSL 5.9.4) on RP2040 ===
#watchdog pipeline TLS ascon down: hung during PUBLISH / echo (connection 0); no progress for 8 s, the board rebooted; continuing with the next block
#block pipeline plain none up
#lib none (plain MQTT)
iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B,hs_writes,hs_reads,writes,reads,free_heap_B
msg,iter,idx,seal_us,rtt_us,open_us,tx_B,rx_B
#err tcp connect failed (no listener?)
#stack 9000
#end
#block sweep TLS MLKEM512
#suite TLS13-AES256-GCM-SHA384
#lib wolfSSL 5.9.4
iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B,hs_writes,hs_reads,writes,reads,free_heap_B,hs_keygen_us,hs_derive_us,hs_verify_us,hs_sign_us,hs_keygen_n,hs_derive_n,hs_verify_n,hs_sign_n
0,4.0,200.0,3.0,207.0,1100,6000,45,300,3,8,4,11,150000,20000.0,21000.0,54000.0,0.0,1,1,2,0
1,4.0,220.0,3.0,227.0,1100,6000,45,300,3,8,4,11,150000,22000.0,23000.0,54000.0,0.0,1,1,2,0
#heap 30000
#end
#block sweep mTLS p521_mlkem1024
#lib wolfSSL 5.9.4
iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B,hs_writes,hs_reads,writes,reads,free_heap_B
#err group not usable by this wolfSSL build
#end
#block kex plain X25519MLKEM768
#lib none (plain MQTT)
iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B,hs_writes,hs_reads,writes,reads,free_heap_B
0,4.0,0.0,3.0,7.0,0,0,23,4,0,0,1,1,150000
#kem X25519MLKEM768 lib=wolfSSL_5.9.4_(small_X25519) pk_B=1216 ct_B=1120 ss_B=64 nist_level=3
kex,iter,idx,keygen_us,rtt_us,decaps_us,encaps_us,tx_B,rx_B
kex,0,0,900000,12000,850000,150,1257,1177
kex,0,1,910000,14000,860000,160,1257,1177
#stack 3000
#end
=== done ===
"""

with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    (d / "certs").symlink_to(ROOT / "certs")
    (d / "scripts").mkdir()
    (d / "scripts/collate_results.py").write_text((ROOT / "scripts/collate_results.py").read_text())
    r.ROOT = str(d)
    os.environ["BROKER"] = "192.168.1.2"
    blocks = r.mqtt_blocks(TXT)
    assert [(b["stage"], b["mode"]) for b in blocks] == [("connect", "plain"), ("connect", "mTLS"), ("connect", "TLS"),
                                                         ("pipeline", "mTLS"), ("pipeline", "TLS"), ("pipeline", "plain"),
                                                         ("sweep", "TLS"), ("sweep", "mTLS"), ("kex", "plain")]
    assert len(blocks[-1]["rows"]) == 1 and len(blocks[-1]["kexs"]) == 2 and blocks[-1]["aead"] == "X25519MLKEM768"
    assert blocks[4]["err"] == "hung during PUBLISH / echo after 1 recorded connections (watchdog reset)"
    assert len(blocks[4]["rows"]) == 1
    assert blocks[5]["stack"] == "9000" and blocks[5]["err"].startswith("tcp connect failed")
    assert blocks[2]["err"] == "tls handshake failed: made-up failure" and not blocks[2]["rows"]
    assert len(blocks[3]["rows"]) == 1 and len(blocks[3]["msgs"]) == 2
    r.save_mqtt(blocks, TXT, "rp2040", "MLDSA44", "rp2040:rp2040:rpipicow")
    s = {x["Mode"]: x for x in csv.DictReader(open(d / "results/mqtt_mtls_summary_pico_rp2040.csv"))}
    assert s["mTLS"]["tls_mean_ms"] == "305.0" and s["mTLS"]["total_tx_B"] == "6045" and s["mTLS"]["peak_heap_B"] == "61000"
    assert s["mTLS"]["free_heap_first_B"] == "150000" and s["mTLS"]["free_heap_last_B"] == "149000"
    assert s["mTLS"]["hs_sign_median_us"] == "209000.0" and s["mTLS"]["hs_verify_n"] == "2.0"  # handshake crypto
    assert s["mTLS"]["hs_keygen_mean_us"] == "91000.0" and not s["plain"].get("hs_keygen_median_us")
    assert s["TLS"]["status"].startswith("tls handshake failed") and s["plain"]["Signature"] == "(plain MQTT reference)"
    p = {x["Mode"]: x for x in csv.DictReader(open(d / "results/pipeline_summary_pico_rp2040.csv"))}
    assert p["mTLS"]["rtt_mean_ms"] == "10.0" and p["mTLS"]["msg_tx_B"] == "101"
    assert (p["mTLS"]["AEAD"], p["mTLS"]["Direction"], p["TLS"]["AEAD"], p["TLS"]["Direction"]) == \
        ("lorawan11", "uplink", "ascon", "downlink")
    assert p["TLS"]["status"] == "PARTIAL: hung during PUBLISH / echo after 1 recorded connections (watchdog reset)"
    assert p["TLS"]["rtt_mean_ms"] == "8.0" and p["TLS"]["free_heap_last_B"] == "90000"   # kept, as PARTIAL
    w = {(x["mode"], x["group"]): x for x in csv.DictReader(open(d / "results/tls_handshake_pure_pico_rp2040.csv"))}
    assert w[("TLS", "MLKEM512")]["median_ms"] == "210.0" and w[("TLS", "MLKEM512")]["hs_tx_B"] == "1100"
    assert w[("TLS", "MLKEM512")]["sig"] == "MLDSA44" and w[("TLS", "MLKEM512")]["status"] == "OK"
    assert w[("mTLS", "p521_mlkem1024")]["n"] == "0" and w[("mTLS", "p521_mlkem1024")]["status"].startswith("group not")
    assert w[("TLS", "MLKEM512")]["hs_derive_median_us"] == "22000.0" and w[("TLS", "MLKEM512")]["hs_sign_n"] == "0.0"
    k = next(csv.DictReader(open(d / "results/kem_exchange_summary_pico_rp2040.csv")))
    assert (k["KEM"], k["library_version"], k["pk_B"], k["ss_B"], k["n"]) == \
        ("X25519MLKEM768", "wolfSSL 5.9.4 (small X25519)", "1216", "64", "2")
    assert k["keygen_median_us"] == "905000.0" and k["encaps_median_us"] == "155.0" and k["status"] == "OK"
    subprocess.run([sys.executable, str(d / "scripts/collate_results.py")], check=True, capture_output=True)
    rows = list(csv.DictReader(open(d / "results/all_results.csv")))
    assert any(x["platform"] == "rp2040" and x["stage"] == "Stage 2 MQTT connect" and x["mode"] == "mTLS"
               and x["operation"] == "tls connect" and x["metric"] == "mean" and x["value"] == "305.0" for x in rows)
    assert any(x["stage"] == "Pipeline" and x["operation"] == "broker round trip" for x in rows)
    assert any(x["metric"] == "peak_heap" and x["value"] == "61000" for x in rows)
    assert any(x["stage"] == "Pipeline" and x["mode"] == "TLS" and x["operation"] == "broker round trip"
               and x["status"].startswith("PARTIAL") for x in rows)
    assert any(x["platform"] == "rp2040" and x["stage"] == "TLS handshake" and x["library"] == "wolfSSL 5.9.4"
               and x["group"] == "MLKEM512" and x["metric"] == "median" and x["value"] == "210.0" for x in rows)
    assert any(x["stage"] == "Stage 2 MQTT connect" and x["mode"] == "mTLS" and x["operation"] == "handshake: sign (client)"
               and x["metric"] == "median" and x["value"] == "209000.0" for x in rows)
    assert any(x["stage"] == "TLS handshake" and x["group"] == "MLKEM512" and x["metric"] == "median"
               and x["operation"] == "handshake: key share completion (client)" and x["value"] == "22000.0" for x in rows)
    assert any(x["platform"] == "rp2040" and x["stage"] == "KEM exchange (MQTT)" and x["algorithm"] == "X25519MLKEM768"
               and x["operation"] == "decapsulate (client)" and x["metric"] == "median" and x["value"] == "855000.0"
               for x in rows)
# a reset that isn't the watchdog's runs the first blocks again: one block per label, the fullest run
H = "iter,tcp_ms,tls_ms,mqtt_ms,total_ms,hs_tx_B,hs_rx_B,mqtt_tx_B,mqtt_rx_B,hs_writes,hs_reads,writes,reads"
dup = r.mqtt_blocks(f"=== x on RP2040 ===\n#block connect plain\n{H}\n0,1,0,1,2,0,0,23,4,0,0,1,1\n1,1,0,1,2,0,0,23,4,0,0,1,1\n"
                    f"#block connect TLS\n=== x on RP2040 ===\n#block connect plain\n{H}\n0,1,0,1,2,0,0,23,4,0,0,1,1\n#end\n")
assert [(b["stage"], b["mode"], len(b["rows"])) for b in dup] == [("connect", "plain", 2), ("connect", "TLS", 0)], dup
# the sketch's sweep groups are the host's (same names, so the Mac / Pi / Pico rows line up)
import re, mqtt_bench as bmm
ino = (PICO / "sketches/mqtt_tls_bench/mqtt_tls_bench.ino").read_text()
names = re.findall(r'\{"(\w+)", WOLFSSL_', ino)
assert len(names) == 13 and set(names) <= set(bmm.SWEEP_GROUPS), set(names) - set(bmm.SWEEP_GROUPS)
print("mqtt_parse_test: OK")
