#!/usr/bin/env python3
"""A signature sketch's serial output -> run_benchmarks.capture, on made-up transcripts (no board, no serial port):
the ESP32's hardware cycles (cyc_src=CCOUNT, board_compat.h) are kept as logged, past 2^32; a log without cyc_src
(the Pico, older ESP32 logs) still gets us x MHz. Run: python3 pico/tests/sig_cycles_parse_test.py"""
import os, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_benchmarks as r

ESP32 = """>>> running, ITERS=2
  iter 1/2 k=14961us s=32949us v=15240us kc=3590640 sc=7907760 vc=3657600
  iter 2/2 k=14614us s=68795us v=15204us kc=3507360 sc=16510800 vc=3648960

=== ML-DSA-44 (mldsa-native, liboqs lineage; ref C path) on ESP32 ===
CPU clock: 240 MHz
sizes: pk=1312 sk=2560 sig=2420 sigMax=2420
ML-DSA-44(mldsa-native)  keygen  n=2  mean=14787us/14.787ms  median=14787us/14.787ms  std=173us/0.173ms  min=14614us  max=14961us  mean_cyc=3549000  median_cyc=3549000  min_cyc=3507360  max_cyc=3590640  cyc_src=CCOUNT  ops/s=67.6270
ML-DSA-44(mldsa-native)  sign  n=1  mean=598477744us/598477.744ms  median=598477744us/598477.744ms  std=0us/0.000ms  min=598477744us  max=598477744us  mean_cyc=143634658560  median_cyc=143634658560  min_cyc=143634658560  max_cyc=143634658560  cyc_src=CCOUNT  ops/s=0.0017
ML-DSA-44(mldsa-native)  verify  n=2  mean=15222us/15.222ms  median=15222us/15.222ms  std=18us/0.018ms  min=15204us  max=15240us  mean_cyc=3653280  median_cyc=3653280  min_cyc=3648960  max_cyc=3657600  cyc_src=CCOUNT  ops/s=65.6944
verify OK: 2/2
=== done (repeats in ~5s) ===
"""
# the same summary as an older log prints it: 32-bit us x MHz (the sign row wrapped), no cyc_src
OLD = ESP32.replace("  cyc_src=CCOUNT", "").replace("mean_cyc=143634658560", "mean_cyc=1897352448")


class FakeSerial:
    def __init__(self, text): self.lines = [l.encode() + b"\n" for l in text.splitlines()]
    def readline(self): return self.lines.pop(0) if self.lines else b""
    def close(self): pass


def run(text):
    r.open_serial = lambda *a, **k: FakeSerial(text)
    with tempfile.TemporaryDirectory() as d:
        rows, sizes, fault, _ = r.capture("FAKE", 5, os.path.join(d, "x.log"), esp=True)
    assert not fault and sizes == (1312, 2560, 2420, 2420), (fault, sizes)
    return rows


new = run(ESP32)
assert new["keygen"]["cyc_src"] == "CCOUNT"
assert new["keygen"]["mean_cyc"] == 3549000 and new["keygen"]["median_cyc"] == 3549000, new["keygen"]
assert new["sign"]["mean_cyc"] == 143634658560, new["sign"]  # > 2^32: kept, not replaced by us x MHz
assert new["verify"]["median_cyc"] == 3653280, new["verify"]

old = run(OLD)
assert old["keygen"]["cyc_src"] == ""
assert old["keygen"]["mean_cyc"] == 14787 * 240, old["keygen"]   # derived
assert old["sign"]["mean_cyc"] == 598477744 * 240, old["sign"]   # the wrapped value replaced
print("sig_cycles_parse_test: OK (hardware cycles kept as logged; older logs still us x MHz)")
