"""mqtt_tls_bench logs -> one CSV row per connect / sweep block (the MQTT/TLS benchmark table).

  python scripts/mqtt_tls_csv.py [out.csv] [logdir ...]
  default: pico/mqtt_tls_benchmarks.csv from pico/logs_pi (ESP32) and pico/logs_pi_broker4 (Pico W)

Logs from the current firmware carry everything: '#board' (chip, core, cores, clock, SRAM, flash, firmware size),
'#build' (wolfSSL / liboqs commits) and per connection total_cyc / wait_cyc (the CPU's cycle counter;
client CPU cycles = total_cyc - wait_cyc). Older logs lack these: the board's datasheet values fill the platform
columns, firmware size stays empty, the commit is the release tag, and the cycles are the handshake crypto's
micros() x clock (marked 'derived' in the Cycle-count method column).
"""
import csv, glob, os, re, statistics, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "pico"))
from run_benchmarks import mqtt_blocks  # the runner's own parser (keeps each block's fullest run after a reset)

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "pico", "mqtt_tls_benchmarks.csv")
DIRS = sys.argv[2:] or [os.path.join(ROOT, "pico", "logs_pi"), os.path.join(ROOT, "pico", "logs_pi_broker4")]

# for logs without a '#board' line: by the banner's "on <chip>"
FALLBACK = {
    "ESP32": dict(Platform="ESP32-WROOM-32 DevKit", model="ESP32", core="Xtensa LX6", cores=2, sram_KB=520, flash_KB=4096),
    "RP2040": dict(Platform="Raspberry Pi Pico W", model="RP2040", core="Arm Cortex-M0+", cores=2, sram_KB=264, flash_KB=2048),
}
PLATFORM = {"ESP32": "ESP32-WROOM-32 DevKit", "RP2040": "Raspberry Pi Pico W", "RP2350": "Raspberry Pi Pico 2 W"}
HS = ("hs_keygen_us", "hs_derive_us", "hs_verify_us", "hs_sign_us")
WOLFSSL_TAG_COMMIT = "3c5eead44"  # v5.9.4-stable, the release make_wolfssl_lib.sh checks out
R3_LIBOQS = "b196b57a"  # run_all.sh's R3_LIBOQS: the round 3 SNOVA

COLS = ["Platform", "MCU", "Core / architecture", "Clock (MHz)", "SRAM (KB)", "Flash (KB)", "Client certificate",
        "Server certificate", "KEX group", "Cipher suite", "TLS library / commit", "Attempts / Campaigns (n)",
        "Successful (n)", "Connect min (ms)", "Connect median (ms)", "Connect max (ms)", "Connect P50 (ms)",
        "Connect P90 (ms)", "Connect P99 (ms)", "Client CPU cycles Min", "Client CPU cycles Median",
        "Client CPU cycles Max", "Client CPU cycles P50", "Client CPU cycles P90", "Client CPU cycles P99",
        "Cycle-count method", "Sent (B)", "Received (B)", "Total traffic (B)", "TLS writes", "TLS reads",
        "Firmware size (KB)", "Peak RAM (KB)", "Block", "Outcome"]


def pct(xs, p):  # linear interpolation, as the signature CSV
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    f = int(k)
    return xs[f] if f + 1 >= len(xs) else xs[f] + (xs[f + 1] - xs[f]) * (k - f)


def cert_name(fname):
    n = re.match(r"MQTT_TLS_(.+?)_wolfSSL", fname)[1]
    m = re.match(r"SNOVA_(I+|V)_(\w)_round_3", n)
    return f"SNOVA-{m[1]}-{m[2]} (round 3)" if m else n


def kv(txt, prefix):  # the last '#<prefix> k=v ...' line (a reset prints it again)
    lines = re.findall(rf"^#{prefix} (.*)$", txt, re.M)
    return dict(re.findall(r"(\w+)=(\S+)", lines[-1])) if lines else {}


rows = []
for d in DIRS:
    for path in sorted(glob.glob(os.path.join(d, "MQTT_TLS_*.log"))):
        txt = open(path, encoding="utf-8", errors="replace").read()
        chip = re.search(r"\) on (\S+) ===", txt)[1]
        clock = int(re.search(r"CPU clock: (\d+) MHz", txt)[1])
        cfg = kv(txt, "config")
        board, build = kv(txt, "board"), kv(txt, "build")
        fb = FALLBACK.get(chip, FALLBACK["RP2040"])
        default_kex = re.search(r"certificates, (\S+) \(", txt)[1]
        cert = cert_name(os.path.basename(path))
        snova = "SNOVA" in cert
        if build:
            lib_base = f"wolfSSL {build['wolfssl']} @ {build['wolfssl_commit']}"
            oqs = build.get("liboqs_commit", "none")
        else:
            lib_base, oqs = f"wolfSSL 5.9.4 @ {WOLFSSL_TAG_COMMIT}", R3_LIBOQS if snova else "none"
        lib_tls = lib_base + (f" + liboqs @ {oqs} (round 3 SNOVA)" if oqs not in ("none", "") else "")
        firmware_kb = f"{int(board['firmware_B']) / 1024:.1f}" if "firmware_B" in board else ""
        cyc_counter = board.get("cycles")
        for b in mqtt_blocks(txt):
            if b["stage"] not in ("connect", "sweep"):
                continue
            plain = b["mode"] == "plain"
            r = b["rows"]
            attempts = int(cfg["iterations"] if b["stage"] == "connect" else cfg["sweep_iterations"])
            row = {
                "Platform": PLATFORM.get(chip, fb["Platform"]),
                "MCU": board.get("model", fb["model"]),
                "Core / architecture": f"{board.get('core', fb['core']).replace('_', ' ')}, "
                                       f"{board.get('cores', fb['cores'])} cores",
                "Clock (MHz)": board.get("cpu_mhz", clock),
                "SRAM (KB)": board.get("sram_KB", fb["sram_KB"]),
                "Flash (KB)": board.get("flash_KB", fb["flash_KB"]),
                "Client certificate": cert if b["mode"] == "mTLS" else "none (plain MQTT)" if plain else "none (server-auth TLS)",
                "Server certificate": "none" if plain else cert,
                "KEX group": "none" if plain else (b["aead"] if b["stage"] == "sweep" else default_kex),
                "Cipher suite": b["suite"] or ("none" if plain else ""),
                "TLS library / commit": "none (plain MQTT)" if plain else lib_tls,
                "Attempts / Campaigns (n)": attempts, "Successful (n)": len(r),
                "Firmware size (KB)": firmware_kb,
                "Block": f"{b['stage']} {b['mode']}" + (f" {b['aead']}" if b["stage"] == "sweep" else ""),
                "Outcome": "OK" if not b["err"] and len(r) == attempts else
                           f"PARTIAL ({len(r)}/{attempts}): {b['err'] or 'fewer connections than configured'}" if r else
                           f"FAILED: {b['err']}",
            }
            if r:
                t = [float(x["total_ms"]) for x in r]
                row.update({"Connect min (ms)": f"{min(t):.3f}", "Connect median (ms)": f"{statistics.median(t):.3f}",
                            "Connect max (ms)": f"{max(t):.3f}", "Connect P50 (ms)": f"{pct(t, .5):.3f}",
                            "Connect P90 (ms)": f"{pct(t, .9):.3f}", "Connect P99 (ms)": f"{pct(t, .99):.3f}"})
                if "total_cyc" in r[0]:  # measured: the connection's cycles less those in the TCP connect and socket calls
                    cyc = [float(x["total_cyc"]) - float(x["wait_cyc"]) for x in r]
                    method = (f"{cyc_counter or 'cycle counter'}: TCP connect..CONNACK minus TCP connect and "
                              "socket read/write calls (measured)")
                elif not plain:  # older logs: the handshake's crypto only, from micros()
                    cyc = [sum(float(x[c]) for c in HS) * clock for x in r]
                    method = f"handshake crypto micros() (keygen+derive+verify+sign) x {clock} MHz (derived)"
                else:
                    cyc = None
                if cyc:
                    row.update({"Client CPU cycles Min": round(min(cyc)), "Client CPU cycles Median": round(statistics.median(cyc)),
                                "Client CPU cycles Max": round(max(cyc)), "Client CPU cycles P50": round(pct(cyc, .5)),
                                "Client CPU cycles P90": round(pct(cyc, .9)), "Client CPU cycles P99": round(pct(cyc, .99)),
                                "Cycle-count method": method})
                md = lambda k: round(statistics.median(int(x[k]) for x in r))
                sent, recv = md("hs_tx_B") + md("mqtt_tx_B"), md("hs_rx_B") + md("mqtt_rx_B")
                row.update({"Sent (B)": sent, "Received (B)": recv, "Total traffic (B)": sent + recv,
                            "TLS writes": "" if plain else md("writes"), "TLS reads": "" if plain else md("reads")})
            if b["heap"] or b["stack"]:  # the block's peak heap (wolfSSL's allocations) + peak stack
                row["Peak RAM (KB)"] = f"{(int(b['heap'] or 0) + int(b['stack'] or 0)) / 1024:.1f}"
            rows.append(row)

with open(OUT, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, COLS, restval="")
    w.writeheader()
    w.writerows(rows)
print(len(rows), "rows ->", OUT)
