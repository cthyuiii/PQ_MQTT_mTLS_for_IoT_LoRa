"""Stage 2 (MQTT over TLS / mutual TLS with PQ X.509 certificates) and the full pipeline, against Mosquitto.

Project plan sections 1.3, 4.1 and 4.2. Only the certificate's signature algorithm
varies. Held constant: the X25519MLKEM768 group (the customer's key exchange, the only group Stage 2 and the
pipeline offer; the broker also accepts the tls sweep's groups), TLS 1.3, the Mosquitto config, the client's MQTT CONNECT,
and the network. Plain MQTT without TLS is the reference row. For every
(client TLS library x signature) it records the mTLS handshake time, the MQTT
CONNECT->CONNACK time, and the handshake bytes in each direction. A combination
that fails is recorded as a result with its reason, not dropped.

Each signature gets its own Mosquitto process: mTLS on port base+1+i, server-auth
TLS on base+101+i (fixed order below), so a remote client needs no port map and
one bad cert cannot take the other listeners down. Modes: plain, TLS, mTLS.

Full pipeline (--messages N): every connection then sends N telemetry PUBLISHes
whose payload is protected end to end, as uplink and downlink frames (--dirs) (--aeads: LoRaWAN 1.0/1.1 AES-CTR+CMAC,
the same frame with AES-256, AES-128/256-GCM, AES-128/256-CCM, Ascon-AEAD128, none) inside the TLS session, through the broker
and back to a subscriber, verified and decrypted:
  PQ handshake (X25519MLKEM768 + PQ certs) -> payload AEAD -> MQTT broker -> subscriber
Default signatures there, as for Stage 2 and on the Pico: every certificate TLS accepts (SIGS_TLS; until 7 Oct only the
customer's shortlist ECDSA-P256, ML-DSA-44, Falcon-512: --sigs ECDSAP256 MLDSA44 FALCON512). Output:
pipeline_{summary,msgs_raw}_<tag>.csv.

  python network/mqtt_bench.py --tag pi5              # broker + client on this host
  python network/mqtt_bench.py --role broker          # on the Pi 5 broker
  python network/mqtt_bench.py --role client --host <broker> --tag pi4
  python network/mqtt_bench.py --messages 200 --aeads lorawan10,aes128gcm,ascon
  python network/mqtt_bench.py --messages 5 --sigs MLDSA44 --watch   # see the messages arrive

--watch (pipeline only) adds an independent subscriber per broker (mqtt_tls_timer in watch mode, on the
server-auth TLS listener, or the plain one). It holds the pipeline's keys, so each line shows a message
as the subscriber received it: time, topic, bytes, FCnt and the verified, decrypted reading. It is a
second delivery for the broker, so keep timing runs without it.

Needs certs/ from gen_certs.sh, network/mqtt_tls_timer (OpenSSL) and,
for the wolfSSL rows, mqtt_tls_timer_wolfssl from build_wolfssl.sh.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from provenance import board_name, versions

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SIGS = ["RSA2048", "RSA3072", "ECDSAP256", "ED25519",
        "MLDSA44", "MLDSA65", "MLDSA87", "FALCON512", "FALCON1024",
        "SLHDSA128F", "SLHDSA128S", "SLHDSA192F"]
# NIST round 3 MAYO / SNOVA: oqs-provider 36cafae (liboqs main), certs in certs/round3 (run_all.sh round3 stage).
# The pinned oqs-provider has only their round 2 sets, which round 3 replaced.
SIGS_R3 = ["MAYO1", "MAYO2", "MAYO3", "MAYO5"] + [f"SNOVA{lvl}{v}" for lvl in "135" for v in "BKS"]
# gen_certs.sh --deploy: the deployment checks' set (ML-DSA-44), served whenever certs/DEPLOY exists: mTLS / TLS with
# server.crt, and two TLS listeners every client must refuse (revoked.crt, expired.crt). --deploy runs the host side.
# the deployment checks' sets (gen_certs.sh --deploy): DEPLOY (ML-DSA-44, + the trust-anchor update and the signed KEM
# exchange) and, with DEPLOY_SIGS=all, the same checks for the other certificate types (appended: ports stay)
SIGS_DEPLOY = ["DEPLOY"] + [f"DEPLOY_{s}" for s in ("RSA2048", "RSA3072", "ECDSAP256", "ED25519", "MLDSA65", "MLDSA87",
                                                    "FALCON512", "FALCON1024")]
PORT_OFFSET = {"mTLS": 0, "TLS": 100, "revoked": 200, "expired": 300}
DEPLOY_KEMS = ["ML-KEM-768", "X25519MLKEM768"]
WRONG_NAME = "192.0.2.1"  # TEST-NET-1: never the broker
CERT_FILES = ("CA.crt", "server.crt", "server.key", "client.crt", "client.key")
# TLS / mTLS runs (Stage 2, the pipeline, the tls sweep, the broker's listeners) by default: every certificate but
# SLH-DSA, which OpenSSL's TLS layer refuses ("ssl_set_cert: unknown certificate type"); --sigs still names them.
# SIGS keeps its order: port_of() numbers the listeners by it.
SIGS_TLS = [s for s in SIGS if not s.startswith("SLHDSA")]
# the tls stage's key exchanges (tls_sweep.sh; the Pico's sweep blocks take those its wolfSSL has: all but the
# last four), OpenSSL names. Lower-case names and SecP256r1MLKEM512 come from oqs-provider. Not BIKE: oqs-provider
# lists bikel1, but the client refuses it in TLS 1.3 ("no suitable groups", OpenSSL 3.6.4 + oqs-provider c174ed7).
SWEEP_GROUPS = ["MLKEM512", "MLKEM768", "MLKEM1024",                              # pure ML-KEM
                "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",      # IETF hybrids (OpenSSL 3.5+)
                "SecP256r1MLKEM512", "x25519_mlkem512", "p384_mlkem768", "p521_mlkem1024", "x448_mlkem768",
                "X25519", "secp256r1",                                             # classical baselines
                "hqc1", "hqc3", "hqc5", "frodo640aes"]                             # other KEM families (HQC: NIST 2025)
# per AES mode, 128- vs 256-bit keys: CTR (LoRaWAN's own; aes256ctr / lorawan11_256 = its 1.0.x / 1.1 frames with 256-bit
# keys), GCM, CCM; + Ascon
AEADS = ["none", "lorawan10", "lorawan11", "aes256ctr", "lorawan11_256", "aes128gcm", "aes256gcm", "aes128ccm", "aes256ccm",
         "ascon", "lorawan11_e2e"]
# the pipeline's default (7 Oct): LoRaWAN 1.1 only, as the standard (AES-128) and in its own construction with 256-bit
# keys. GCM / CCM / Ascon use their own frame (16 B tag), which no LoRaWAN network server reads; --aeads adds them.
# lorawan11_e2e (branch LoRa_1.1_implementation): the standard 1.1 frame around an AES-256 layer only the application
# removes, the 256-bit path a stock network server (ChirpStack) accepts
AEADS_DEFAULT = ["lorawan11", "lorawan11_256", "lorawan11_e2e"]
TIMERS = [("OpenSSL", HERE / "mqtt_tls_timer"), ("wolfSSL", HERE / "mqtt_tls_timer_wolfssl")]
KEX_TIMER = HERE / "mqtt_kem_timer"   # the timer with liboqs (build_timer.sh): the KEM exchange's client + responder
# --kex: KEM exchange as MQTT messages through the broker (liboqs names): Classic McEliece (public keys too big for a
# TLS 1.3 key share) and HQC, with ML-KEM-768 as the reference. SIKE is left out: broken in 2022, gone from liboqs.
KEX_KEMS = ["ML-KEM-768", "X25519MLKEM768", "X25519", "HQC-1", "HQC-3", "HQC-5", "Classic-McEliece-348864",
            "Classic-McEliece-460896", "Classic-McEliece-6688128", "Classic-McEliece-6960119", "Classic-McEliece-8192128"]


# the client's crypto inside each handshake, when the client times it (pico/sketches/mqtt_tls_bench/hs_timing.c: the Pico, and
# the wolfSSL client on Linux; network/hs_timing_openssl.c: the OpenSSL client on Linux): key share, its completion
# (decapsulation / shared secret), verify, sign; us and calls
HS_COLS = ("hs_keygen_us", "hs_derive_us", "hs_verify_us", "hs_sign_us", "hs_keygen_n", "hs_derive_n", "hs_verify_n",
           "hs_sign_n")


def port_of(base: int, sig: str, mode: str = "mTLS") -> int:
    return base + 1 + (SIGS + SIGS_R3 + SIGS_DEPLOY).index(sig) + PORT_OFFSET[mode]


def der_bytes(pem: Path) -> int:
    body = "".join(line for line in pem.read_text().splitlines() if line and not line.startswith("-----"))
    return len(base64.b64decode(body))


def openssl_cnf(tmp: Path, group: str) -> Path:
    """The customer's openssl-pqc.cnf: default (+ oqsprovider if loadable). Groups: the Stage 2 group and the tls
    sweep's (tls_sweep.sh uses these listeners too). Each client offers exactly one group, so Stage 2
    still always gets its own. '?' (OpenSSL 3.5+): a group this OpenSSL lacks (no oqs-provider) is skipped, not fatal."""
    groups = ":".join(f"?{g}" for g in dict.fromkeys([group, *SWEEP_GROUPS]))
    ossl = os.environ.get("OSSL", "openssl")
    oqs = subprocess.run([ossl, "list", "-providers", "-provider", "oqsprovider"],
                         capture_output=True).returncode == 0
    providers = "default = default_sect\n" + ("oqsprovider = oqsprovider_sect\n" if oqs else "")
    cnf = tmp / "openssl-pqc.cnf"
    cnf.write_text(
        "openssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\nssl_conf = ssl_sect\n"
        f"[provider_sect]\n{providers}[default_sect]\nactivate = 1\n"
        + ("[oqsprovider_sect]\nactivate = 1\n" if oqs else "")
        + f"[ssl_sect]\nsystem_default = system_default_sect\n[system_default_sect]\nGroups = {groups}\n")
    if not oqs:
        print("[i] oqsprovider not loadable: Falcon/MAYO/SNOVA listeners will fail (set OPENSSL_MODULES)")
    return cnf


def is_local(host: str) -> bool:
    """host is this machine (loopback or one of its own addresses): binding to an address works only there.
    Such runs measure no network, so collate_results.py leaves them out."""
    try:
        with socket.socket() as s:
            s.bind((host, 0))
        return True
    except OSError:
        return False


def wait_port(host: str, port: int, proc: subprocess.Popen, secs: float = 5.0) -> bool:
    deadline = time.monotonic() + secs
    while time.monotonic() < deadline and proc.poll() is None:
        try:
            socket.create_connection((host, port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


BROKER_HS_COLS = "unix_time,client_ip,port,group,total_us,keygen_us,encaps_us,derive_us,sign_us,verify_us,calls"


def broker_hs_files(args) -> tuple[Path, Path]:
    """the broker's side of the handshakes (broker_hs_timing.c): raw lines, appended; the summary, per broker run"""
    tag = (args.tag or board_name()) + ("" if args.base_port == 18830 else f"_{args.base_port}")
    return args.results_dir / f"broker_hs_raw_{tag}.csv", args.results_dir / f"broker_hs_summary_{tag}.csv"


def broker_hs_env(args) -> dict:
    """preload broker_hs_timing.c's library into Mosquitto (build_timer.sh builds it), when there is one"""
    lib = next((p for p in (HERE / "libbroker_hs.so", HERE / "libbroker_hs.dylib") if p.exists()), None)
    if not lib:
        return {}
    raw, _ = broker_hs_files(args)
    raw.parent.mkdir(parents=True, exist_ok=True)
    if not raw.exists():
        raw.write_text(BROKER_HS_COLS + "\n")
    return {"DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD": str(lib), "BROKER_HS_LOG": str(raw)}


def broker_hs_summary(args):
    """broker_hs_raw -> per client, certificate, mode and group: medians of the broker's handshake time and its crypto"""
    raw, out = broker_hs_files(args)
    if not raw.exists():
        return
    where = {port_of(args.base_port, sig, mode): (sig, mode) for sig in SIGS + SIGS_R3 + SIGS_DEPLOY for mode in PORT_OFFSET}
    groups = {}
    for r in csv.DictReader(raw.open()):
        sig, mode = where.get(int(r["port"]), ("?", "?"))
        groups.setdefault((r["client_ip"], sig, mode, r["group"]), []).append(r)
    rows = []
    for (ip, sig, mode, group), rs in sorted(groups.items()):
        med = lambda k: statistics.median(float(x[k]) for x in rs)
        crypto = [sum(float(x[k]) for k in ("keygen_us", "encaps_us", "derive_us", "sign_us", "verify_us")) for x in rs]
        rows.append(dict(Board=args.board or board_name(), client_ip=ip, Signature=sig, Mode=mode, Group=group, n=len(rs),
                         total_median_us=med("total_us"), total_mean_us=statistics.fmean(float(x["total_us"]) for x in rs),
                         **{f"{k[:-3]}_median_us": med(k) for k in ("keygen_us", "encaps_us", "derive_us", "sign_us", "verify_us")},
                         crypto_median_us=statistics.median(crypto)))
    if rows:
        write_csv(out, rows)
        print(f"[broker] the broker's side of {sum(r['n'] for r in rows)} handshakes -> {out}")


# BROKER_ACL=1 (the ChirpStack set-up's broker, README 0.4): an ACL on each certificate's listeners. mTLS, by client
# certificate name (use_identity_as_username): the benchmark clients and devices (pqc-client) keep pqc/, ChirpStack
# publishes its events and reads its commands, the application the reverse. The server-auth TLS listener shares the
# process and so the topics: its anonymous clients get pqc/ only, never ChirpStack's events
ACL_MTLS = ("user pqc-client\ntopic readwrite pqc/#\n"
            "user chirpstack\ntopic write application/+/device/+/event/#\ntopic read application/+/device/+/command/#\n"
            "user application\ntopic read application/+/device/+/event/#\ntopic write application/+/device/+/command/#\n")
ACL_TLS = "topic readwrite pqc/#\n"


def start_brokers(args, tmp: Path, bind: str):
    """One Mosquitto per listener. Returns (processes, {sig: failure reason})."""
    env = dict(os.environ, OPENSSL_CONF=str(openssl_cnf(tmp, args.group)), **broker_hs_env(args))
    common = ["per_listener_settings true", "log_dest stderr", "log_type error", "log_type warning",
              "log_type notice",  # notice: one line per connection, which follow_logs() shows on the broker machine
              "set_tcp_nodelay true"]  # no Nagle: a small CONNACK after the TLS 1.3 session tickets goes out at once
    procs, failed = [], {}
    acl = os.environ.get("BROKER_ACL", "") not in ("", "0")
    if acl:
        (tmp / "acl_mtls").write_text(ACL_MTLS)
        (tmp / "acl_tls").write_text(ACL_TLS)
    acl_file = lambda f: [f"acl_file {tmp / f}"] if acl else []

    def launch(name, port, extra):
        conf = tmp / f"{name}.conf"
        conf.write_text("\n".join(common + [f"listener {port} {bind}".rstrip()] + extra) + "\n")
        log = tmp / f"{name}.log"
        p = subprocess.Popen([args.mosquitto, "-c", str(conf)], env=env,
                             stdout=subprocess.DEVNULL, stderr=log.open("w"))
        if wait_port(bind or "127.0.0.1", port, p):
            procs.append(p)
            return None
        p.kill()
        p.wait()
        lines = [ln for ln in log.read_text().splitlines() if "rror" in ln] or log.read_text().splitlines()
        return "broker could not start listener: " + (re.sub(r"^\d+: ", "", lines[-1]) if lines else "unknown")

    if (err := launch("plain", args.base_port, ["allow_anonymous true"])):
        raise SystemExit(f"plain MQTT listener failed ({err}) - port {args.base_port} in use?")
    for sig in args.sigs:
        src = args.certs / sig
        if not all((src / f).exists() for f in CERT_FILES):
            failed[sig] = "no certificate (gen_certs.sh could not create it with this OpenSSL/oqsprovider)"
            continue
        d = tmp / sig  # private copy: Mosquitto config values cannot contain spaces
        shutil.copytree(src, d, dirs_exist_ok=True)
        # cafile = the client CA (gen_certs.sh): OpenSSL fills the broker's chain from this store, and without the
        # server's issuer in it the broker sends only its own certificate, not the CA every client already holds
        ca = "ClientCA.crt" if (src / "ClientCA.crt").exists() else "CA.crt"
        tls = ["tls_version tlsv1.3", f"cafile {d}/{ca}", f"certfile {d}/server.crt", f"keyfile {d}/server.key"]
        err = launch(sig, port_of(args.base_port, sig), [
            "allow_anonymous false", "require_certificate true", "use_identity_as_username true", *tls,
            *acl_file("acl_mtls"),
            f"listener {port_of(args.base_port, sig, 'TLS')} {bind}".rstrip(),   # server-auth TLS
            "allow_anonymous true", "require_certificate false", *tls, *acl_file("acl_tls")])
        if err:
            failed[sig] = err
    for ds in SIGS_DEPLOY:  # the deployment checks' listeners per set present, and DEPLOY's signed trust-anchor update
        d = args.certs / ds
        if not (d / "CA.crl").exists():
            continue
        t = tmp / ds
        shutil.copytree(d, t, dirs_exist_ok=True)
        tls = lambda c, t=t: ["tls_version tlsv1.3", f"cafile {t}/ClientCA.crt", f"certfile {t}/{c}.crt", f"keyfile {t}/{c}.key"]
        listener = lambda m, c, ds=ds, tls=tls: [f"listener {port_of(args.base_port, ds, m)} {bind}".rstrip(),
                                                 "allow_anonymous true", "require_certificate false", *tls(c)]
        err = launch(ds, port_of(args.base_port, ds), [
            "allow_anonymous false", "require_certificate true", "use_identity_as_username true", *tls("server"),
            *listener("TLS", "server"), *listener("revoked", "revoked"), *listener("expired", "expired")])
        if err:
            failed[ds] = err
        elif (d / "ta_update.bin").exists():  # retained: a device that subscribes gets it at once
            publish_retained(args.base_port, "pqc/ta/update", (d / "ta_update.bin").read_bytes())
    return procs, failed


def publish_retained(port: int, topic: str, payload: bytes):
    """a retained QoS 0 PUBLISH on this machine's plain listener (MQTT 3.1.1: CONNECT, PUBLISH, DISCONNECT)"""
    def varint(n):
        out = b""
        while True:
            out += bytes([n & 0x7F | (0x80 if n > 0x7F else 0)])
            n >>= 7
            if not n:
                return out
    with socket.create_connection(("127.0.0.1", port), 5) as so:
        body = b"\x00\x04MQTT\x04\x02\x00\x3c\x00\x06pqc-ta"
        so.sendall(b"\x10" + varint(len(body)) + body)
        so.recv(4)  # CONNACK
        t = topic.encode()
        body = len(t).to_bytes(2, "big") + t + payload
        so.sendall(b"\x31" + varint(len(body)) + body + b"\xe0\x00")


def run_timer(exe: Path, argv: list[str], args, aead: str, extra_env: dict | None = None):
    """-> dict(lib, suite, rows = per connection, msgs = per message, wholes = per connection, the pipeline as a
    whole, err)."""
    env = dict(os.environ, GROUP=args.group, AEAD=aead, MSGS=str(args.messages), PAYLOAD=str(args.payload),
               DOWN=str(args.down), **(extra_env or {}))
    if args.app_keys:
        env["APP_KEYS"] = args.app_keys
    if args.suite:
        env["SUITE"] = args.suite
    try:
        r = subprocess.run([str(exe), *argv], capture_output=True, text=True, timeout=args.timeout, env=env)
    except subprocess.TimeoutExpired:
        return dict(lib=None, suite="", rows=[], msgs=[], wholes=[], err=f"timed out after {args.timeout:.0f}s")
    lines = r.stdout.splitlines()
    tag = lambda t: next((ln[len(t) + 2:] for ln in lines if ln.startswith(f"#{t} ")), "")
    body = [ln for ln in lines if not ln.startswith("#")]
    err = None if r.returncode == 0 else (r.stderr.strip().splitlines() or ["exit %d" % r.returncode])[-1]
    return dict(lib=tag("lib") or None, suite=tag("suite"), err=err,
                rows=list(csv.DictReader(ln for ln in body if not ln.startswith(("msg", "whole")))),
                msgs=list(csv.DictReader(ln for ln in body if ln.startswith("msg"))),
                wholes=list(csv.DictReader(ln for ln in body if ln.startswith("whole"))))


WIRE_HDR_B = 52  # per TCP segment: IPv4 20 + TCP 20 + timestamps 12 (wire_stats.h); link layer not included


def stats(prefix: str, xs: list[float], unit: str) -> dict:
    """mean, median, population std, min, max of xs -> {prefix_mean_unit: ...}"""
    return {f"{prefix}_mean_{unit}": statistics.fmean(xs), f"{prefix}_median_{unit}": statistics.median(xs),
            f"{prefix}_std_{unit}": statistics.pstdev(xs), f"{prefix}_min_{unit}": min(xs), f"{prefix}_max_{unit}": max(xs)}


def summarize(common: dict, rows: list[dict], msgs: list[dict], wholes: list[dict] = ()) -> dict:
    """Times: mean / median / std / min / max. Bytes and counts: the median connection. up = tx (client ->
    broker), down = rx; hs = the TLS handshake, total = TCP + TLS + MQTT CONNECT / CONNACK; writes / reads =
    socket calls; wire = bytes + 52 B per TCP segment (an estimate; meaningful between two machines).
    The pipeline as a whole, per connection: whole_first = TCP connect -> TLS -> MQTT CONNECT -> SUBSCRIBE -> the
    first reading sealed, through the broker and verified (the single number); whole_all = to the last reading."""
    out = dict(common, n=len(rows))
    for m in ("tcp_ms", "tls_ms", "mqtt_ms", "total_ms"):
        out.update(stats(m[:-3], [float(r[m]) for r in rows], "ms"))
    med = lambda k: int(statistics.median(int(r[k]) for r in rows)) if rows and k in rows[0] else None
    for b in ("hs_tx_B", "hs_rx_B", "mqtt_tx_B", "mqtt_rx_B", "hs_writes", "hs_reads", "writes", "reads",
              "tx_segs", "rx_segs"):
        out[b] = med(b)
    for c in HS_COLS:  # present when the client times its handshake crypto (hs_timing.c)
        if rows and c in rows[0]:
            v = [float(r[c]) for r in rows]
            out.update(stats(c[:-3], v, "us") if c.endswith("_us") else {c: statistics.median(v)})
    out["total_tx_B"], out["total_rx_B"] = out["hs_tx_B"] + out["mqtt_tx_B"], out["hs_rx_B"] + out["mqtt_rx_B"]
    out["total_B"] = out["total_tx_B"] + out["total_rx_B"]
    if out["tx_segs"] is not None:
        out["wire_tx_B"] = out["total_tx_B"] + out["tx_segs"] * WIRE_HDR_B
        out["wire_rx_B"] = out["total_rx_B"] + out["rx_segs"] * WIRE_HDR_B
        out["wire_B"] = out["wire_tx_B"] + out["wire_rx_B"]
    if msgs:  # full pipeline: per-message seal / broker round trip / open, and bytes on the wire
        f = lambda k: [float(m[k]) for m in msgs]
        e2e = sorted((float(m["seal_us"]) + float(m["rtt_us"]) + float(m["open_us"])) / 1e3 for m in msgs)
        out.update(msgs=len(msgs), **stats("seal", f("seal_us"), "us"), **stats("open", f("open_us"), "us"),
                   **stats("rtt", [x / 1e3 for x in f("rtt_us")], "ms"), **stats("e2e", e2e, "ms"),
                   e2e_p90_ms=e2e[int(0.9 * (len(e2e) - 1))],
                   msg_tx_B=int(statistics.median(f("tx_B"))), msg_rx_B=int(statistics.median(f("rx_B"))))
        air = [float(m["air_us"]) for m in msgs if m.get("air_us")]  # the Pico's UDP uplink to the air (ChirpStack runs)
        if air:
            out.update(**stats("air", air, "us"))
    if wholes:
        out.update(**stats("whole_first", [float(w["first_ms"]) for w in wholes], "ms"),
                   **stats("whole_all", [float(w["all_ms"]) for w in wholes], "ms"))
    return out


def run_clients(args, broker_failed: dict):
    board, summary, raw = args.board or board_name(), [], []
    timers = [(name, exe) for name, exe in TIMERS if exe.exists()
              and (not args.clients or any(c.strip().lower() in name.lower() for c in args.clients.split(",")))]
    if not timers:
        raise SystemExit("build network/mqtt_tls_timer first (see its header)")

    def record(lib_name, sig, mode, aead, res, certs=(None, None)):
        common = dict(Board=board, Library=lib_name, Signature=sig, Group="" if mode == "plain" else args.group,
                      Mode=mode, AEAD=aead if args.messages else "",
                      Direction=("downlink" if args.down else "uplink") if args.messages else "",
                      TLS_suite=res.get("suite", ""),
                      status=res["err"] or "OK", server_cert_B=certs[0], client_cert_B=certs[1],
                      library_version=res.get("lib"))
        ok = res["rows"] and not res["err"]
        summary.append(summarize(common, res["rows"], res["msgs"], res.get("wholes", [])) if ok else dict(common, n=0))
        rows = res["msgs"] if args.messages else res["rows"]
        raw.extend(dict(Board=board, Library=lib_name, Signature=sig, Mode=mode, AEAD=aead, Direction=common["Direction"],
                        **r) for r in rows)
        s = summary[-1]
        line = (f"TLS p50 {s['tls_median_ms']:7.2f} ms  MQTT p50 {s['mqtt_median_ms']:5.2f} ms  "
                f"hs tx/rx {s['hs_tx_B']:>6}/{s['hs_rx_B']:<6} B  w/r {s['writes']}/{s['reads']}") if s["n"] else f"-> {s['status']}"
        if s["n"] and args.messages:
            line += (f"  | {aead:<9} {common['Direction']:<8} e2e p50 {s['e2e_median_ms']:.3f} ms  seal {s['seal_mean_us']:.2f} us"
                     f"  {s['msg_tx_B']} B/msg" + (f"  whole p50 {s['whole_first_median_ms']:.2f} ms" if "whole_first_median_ms" in s else ""))
        print(f"  {lib_name:<8} {sig:<21} {mode:<5} {line}")

    modes = [m.strip().lower() for m in args.modes.split(",")]
    for aead, args.down in [(a, d) for a in (args.aeads if args.messages else ["none"])
                            for d in (args.dirs if args.messages else [0])]:
        if "plain" in modes:  # reference row: no TLS at all
            res = run_timer(timers[0][1], [args.host, str(args.base_port), str(args.iterations),
                                           str(args.warmup)], args, aead)
            record("none", "(plain MQTT reference)", "plain", aead, res)
        for lib_name, exe in timers:
            for sig in args.sigs:
                d = args.certs / sig
                certs = ((der_bytes(d / "server.crt"), der_bytes(d / "client.crt"))
                         if (d / "client.crt").exists() else (None, None))
                for mode in [m for m in ("TLS", "mTLS") if m.lower() in modes]:
                    if sig in broker_failed:
                        record(lib_name, sig, mode, aead, dict(err=broker_failed[sig], rows=[], msgs=[]), certs)
                        continue
                    argv = [args.host, str(port_of(args.base_port, sig, mode)), str(args.iterations),
                            str(args.warmup), str(d / "CA.crt")]
                    if mode == "mTLS":
                        argv += [str(d / "client.crt"), str(d / "client.key")]
                    record(lib_name, sig, mode, aead, run_timer(exe, argv, args, aead), certs)
    return summary, raw


def follow_logs(tmp: Path, args):
    """--role broker: until Ctrl-C, one line per connection a broker accepts (its listener = certificate and TLS /
    mTLS), the client certificate an mTLS client presented, and every error. Read from the brokers' log files."""
    label = {args.base_port: "plain MQTT"}
    for sig in args.sigs:
        label[port_of(args.base_port, sig)], label[port_of(args.base_port, sig, "TLS")] = f"{sig} mTLS", f"{sig} TLS"
    conn = re.compile(r"New connection from (\S+):\d+ on port (\d+)")
    client = re.compile(r"New client connected from (\S+):\d+ as (\S+) \(")
    pos = {log: log.stat().st_size for log in tmp.glob("*.log")}  # from now on: startup is already reported
    while True:
        for log in sorted(tmp.glob("*.log")):
            with log.open() as f:
                f.seek(pos.get(log, 0))
                lines, pos[log] = f.readlines(), f.tell()
            for ln in (re.sub(r"^\d+: ", "", x.strip()) for x in lines):
                t = time.strftime("%H:%M:%S")
                if m := conn.search(ln):
                    print(f"[broker {t}] {m[1]} -> :{m[2]} {label.get(int(m[2]), '?')}: new connection")
                elif m := client.search(ln):
                    cert = re.search(r"u'([^']*)'", ln)
                    print(f"[broker {t}] {m[1]} MQTT CONNECT as {m[2]}"
                          + (f", client certificate '{cert[1]}' (mTLS)" if cert else ""))
                elif "unexpected eof while reading" in ln:  # a TLS client gone without close_notify
                    print(f"[broker {t}] {log.stem}: a TLS client disconnected without closing TLS (normal when a "
                          "stage's --watch subscribers are stopped; a Pico Wi-Fi stall looks the same)")
                elif "rror" in ln or ("disconnected:" in ln and "closed by client" not in ln):
                    print(f"[broker {t}] {log.stem}: {ln}")  # failed handshakes, refused certificates, drops
        time.sleep(0.2)


def start_watchers(args, broker_failed: dict) -> list:
    """--watch: one subscriber per broker, printing what it receives to this terminal."""
    exe, procs = TIMERS[0][1], []
    env = dict(os.environ, SUB="pqc/pipe/#", **({"APP_KEYS": args.app_keys} if args.app_keys else {}))
    targets = [("plain", [args.host, str(args.base_port), "1", "0"])] if "plain" in args.modes.lower() else []
    targets += [(sig, [args.host, str(port_of(args.base_port, sig, "TLS")), "1", "0", str(args.certs / sig / "CA.crt")])
                for sig in args.sigs if sig not in broker_failed]
    out = args.watch_log.open("w") if args.watch_log else None  # None = this terminal
    for name, argv in targets:
        procs.append(subprocess.Popen([str(exe), *argv], env=dict(env, WATCH_NAME=name), stdout=out))
    time.sleep(1)  # subscribed before the first PUBLISH
    return procs


def start_kem_responder(args) -> list:
    """the KEM exchange's responder, on the plain listener of this machine's broker (needs the liboqs timer)"""
    exe = KEX_TIMER
    if not exe.exists():
        print("[i] no mqtt_kem_timer (build_timer.sh builds it once liboqs is installed): no KEM responder")
        return []
    d, env = args.certs / "DEPLOY", dict(os.environ, KEM_RESPOND="1")
    runs = [[str(exe), "127.0.0.1", str(args.base_port), "1", "0"]]
    if (d / "ta_update.bin").exists():  # the deployment checks: signed exchanges here, and one responder inside mTLS
        env.update(KEM_SIGN_KEY=str(d / "server.key"), KEM_PEER_CERT=str(d / "client.crt"), KEM_PEER_CA=str(d / "ClientCA.crt"))
        runs.append([str(exe), "127.0.0.1", str(port_of(args.base_port, "DEPLOY")), "1", "0", str(d / "CA.crt"),
                     str(d / "client.crt"), str(d / "client.key")])
    procs = [subprocess.Popen(r, env=env) for r in runs]
    time.sleep(0.5)
    for p in procs:
        if p.poll() is not None:
            print("[i] a KEM responder is not running (see its error above)")
    return [p for p in procs if p.poll() is None]


def run_kex(args) -> tuple[list[dict], list[dict]]:
    """--kex: per KEM, one plain MQTT connection with kex_n exchanges (+ warm-up) through the broker ->
    (summary per KEM, raw per exchange). Times: keygen / decaps on this client, encaps on the responder, rtt = PUBLISH
    of the public key until the ciphertext is back (network + broker + encaps), total = keygen + rtt + decaps."""
    exe, board = KEX_TIMER, args.board or board_name()
    summary, raw = [], []
    if not exe.exists():
        raise SystemExit("no network/mqtt_kem_timer: run build_timer.sh openssl with liboqs installed")
    for kem in args.kex:
        base, rows = kex_once(args, board, kem, kem, [args.host, str(args.base_port), "1", "0"], {})
        summary.append(base)
        raw += rows
    return summary, raw


def kex_once(args, board, kem, label, argv, extra_env):
    """one KEM's exchanges through mqtt_kem_timer -> (summary row, raw rows), printed as they finish"""
    print(f"  {label:<26} running {args.kex_n} + {args.kex_warmup} exchanges ...", flush=True)  # McEliece keygen: seconds each
    env = dict(os.environ, KEM=kem, KEXS=str(args.kex_n), KEX_WARM=str(args.kex_warmup), GROUP=args.group, **extra_env)
    try:
        r = subprocess.run([str(KEX_TIMER), *argv], capture_output=True, text=True, timeout=max(args.timeout, 3600), env=env)
        lines = r.stdout.splitlines()
        err = None if r.returncode == 0 else (r.stderr.strip().splitlines() or [f"exit {r.returncode}"])[-1]
    except subprocess.TimeoutExpired:
        lines, err = [], "timed out"
    info = dict(re.findall(r"(\w+)=(\S+)", next((ln for ln in lines if ln.startswith("#kem ")), "")))
    base, rows = kex_summary(board, label, info, list(csv.DictReader(ln for ln in lines if ln.startswith("kex"))), err)
    print(f"  {label:<26} {base['status'][:60]:<60} n={len(rows)}"
          + (f"  keygen {base['keygen_median_us']:.0f} us  rtt {base['rtt_median_ms']:.2f} ms  decaps "
             f"{base['decaps_median_us']:.0f} us  up {base['pk_B']} B" if rows else ""))
    return base, rows


def run_deploy(args):
    """--deploy: the deployment checks against the broker's deployment listeners (gen_certs.sh --deploy <broker IP>), per
    set present (DEPLOY and any DEPLOY_<SIG>) and per client (OpenSSL, and wolfSSL when built; --clients picks)
    -> (connect summary, connect raw, refused rows, kex summary, kex raw):
      connect TLS / mTLS, and each -checked: CHECK_HOST = the broker's address (--host), CHECK_CRL = the CA's CRL;
      refuse  a wrong broker name, revoked.crt, expired.crt: each connection must fail (dates: both clients check);
      kex     DEPLOY only (OpenSSL + liboqs): ML-KEM-768 and X25519MLKEM768 over plain MQTT, over mTLS and signed
              (ML-DSA-44 on both messages)."""
    board = args.board or board_name()
    sets = [ds for ds in SIGS_DEPLOY if (args.certs / ds / "CA.crl").exists()]
    if not sets:
        raise SystemExit(f"no deployment sets in {args.certs}: run scripts/gen_certs.sh --deploy <broker IP> "
                         "(DEPLOY_SIGS=all for every certificate type), then copy certs/ to both machines")
    timers = [(name, exe) for name, exe in TIMERS if exe.exists()
              and (not args.clients or any(c.strip().lower() in name.lower() for c in args.clients.split(",")))]
    if not timers:
        raise SystemExit("build network/mqtt_tls_timer first (build_timer.sh openssl; wolfssl for the wolfSSL client)")
    summary, raw, refused = [], [], []
    for ds in sets:
        d = args.certs / ds
        certs = (der_bytes(d / "server.crt"), der_bytes(d / "client.crt"))
        ca, mtls_files = str(d / "CA.crt"), [str(d / "client.crt"), str(d / "client.key")]
        checks = dict(CHECK_HOST=args.host, CHECK_CRL=str(d / "CA.crl"))
        for lib, exe in timers:
            for mode in ("TLS", "mTLS"):
                for checked in (False, True):
                    m = mode + ("-checked" if checked else "")
                    argv = [args.host, str(port_of(args.base_port, ds, mode)), str(args.iterations), str(args.warmup), ca]
                    res = run_timer(exe, argv + (mtls_files if mode == "mTLS" else []), args, "none", checks if checked else None)
                    common = dict(Board=board, Library=lib, Signature=ds, Group=args.group, Mode=m, AEAD="",
                                  Direction="", TLS_suite=res.get("suite", ""), status=res["err"] or "OK", server_cert_B=certs[0],
                                  client_cert_B=certs[1] if mode == "mTLS" else None, library_version=res.get("lib"))
                    summary.append(summarize(common, res["rows"], []) if res["rows"] and not res["err"] else dict(common, n=0))
                    raw += [dict(Board=board, Library=lib, Signature=ds, Mode=m, **r) for r in res["rows"]]
                    s = summary[-1]
                    print(f"  {lib:<8} {ds:<18} {m:<13} " + (f"TLS p50 {s['tls_median_ms']:7.2f} ms" if s["n"] else f"-> {s['status']}"))
            for case, port, env in (("wrong-name", "TLS", dict(CHECK_HOST=WRONG_NAME)), ("revoked", "revoked", checks),
                                    ("expired", "expired", {})):
                res = run_timer(exe, [args.host, str(port_of(args.base_port, ds, port)), "1", "0", ca], args, "none", env)
                refused.append(dict(Board=board, Library=lib, Signature=ds, block=f"refuse TLS {case}",
                                    status="OK" if res["err"] else "accepted: it should have been refused",
                                    reason=res["err"] or "", refused=int(bool(res["err"]))))
                print(f"  {lib:<8} {ds:<18} refuse {case:<11} {refused[-1]['status']}  ({refused[-1]['reason'][:60]})")
    kex, kraw = [], []
    d = args.certs / "DEPLOY"
    if (d / "ta_update.bin").exists() and KEX_TIMER.exists():
        ca, mtls_files = str(d / "CA.crt"), [str(d / "client.crt"), str(d / "client.key")]
        signed = dict(KEM_SIGN_KEY=str(d / "client.key"), KEM_PEER_CERT=str(d / "server.crt"), KEM_PEER_CA=ca)
        for kem in DEPLOY_KEMS:
            for mode, argv, env in (("plain", [args.host, str(args.base_port), "1", "0"], {}),
                                    ("mTLS", [args.host, str(port_of(args.base_port, "DEPLOY")), "1", "0", ca, *mtls_files], {}),
                                    ("signed", [args.host, str(args.base_port), "1", "0"], signed)):
                base, rows = kex_once(args, board, kem, f"{kem} {mode}", argv, env)
                kex.append(base)
                kraw += rows
    elif (d / "ta_update.bin").exists():
        print("  [!] no mqtt_kem_timer: the KEM exchange is skipped (build_timer.sh, liboqs installed)")
    return summary, raw, refused, kex, kraw


def kex_summary(board: str, kem: str, info: dict, rows: list[dict], err) -> tuple[dict, list[dict]]:
    """one KEM's '#kem' fields + 'kex' rows -> (summary row, raw rows): the host's --kex and the Pico's kex blocks"""
    base = dict(Board=board, KEM=kem, library_version=info.get("lib", "").replace("_", " ").replace("+", " + "),
                nist_level=info.get("nist_level", ""), pk_B=info.get("pk_B", ""), ct_B=info.get("ct_B", ""),
                ss_B=info.get("ss_B", ""), status="OK" if not err else f"PARTIAL: {err}" if rows else err, n=len(rows))
    if rows:
        f = lambda k: [float(x[k]) for x in rows]
        total = [float(x["keygen_us"]) / 1e3 + float(x["rtt_us"]) / 1e3 + float(x["decaps_us"]) / 1e3 for x in rows]
        for op in ("keygen", "encaps", "decaps") + (("sign", "verify") if "sign_us" in rows[0] else ()):  # signed: the device's
            base.update(stats(op, f(f"{op}_us"), "us"))
        base.update(stats("rtt", [v / 1e3 for v in f("rtt_us")], "ms"), rtt_p90_ms=sorted(f("rtt_us"))[int(.9 * len(rows))] / 1e3)
        base.update(stats("total", total, "ms"), total_p90_ms=sorted(total)[int(.9 * len(total))])
        base.update(tx_B=statistics.median(f("tx_B")), rx_B=statistics.median(f("rx_B")))
    return base, [dict(Board=board, KEM=kem, **{k: v for k, v in x.items() if k != "kex"}) for x in rows]


def write_csv(path: Path, rows: list[dict]):
    fields = list(dict.fromkeys(k for r in rows for k in r))  # union, first-seen order
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--role", choices=("both", "broker", "client"), default="both")
    ap.add_argument("--host", default="127.0.0.1", help="broker address (client role)")
    ap.add_argument("--base-port", type=int, default=18830, help="plain MQTT; signature i listens on base+1+i")
    ap.add_argument("--sigs", nargs="+", choices=SIGS + SIGS_R3, default=None,
                    help="default: all (Stage 2) or ECDSAP256 MLDSA44 FALCON512 (pipeline)")
    ap.add_argument("--match", default="", help="comma list: keep signatures matching any (e.g. mldsa,falcon512)")
    ap.add_argument("--clients", default="", help="comma list of client TLS libraries: openssl,wolfssl")
    ap.add_argument("--group", default="X25519MLKEM768", help="held constant for every signature")
    ap.add_argument("--modes", default="plain,tls,mtls", help="comma list of plain, tls, mtls")
    ap.add_argument("--messages", type=int, default=0, help="> 0 = full pipeline: telemetry messages per connection")
    ap.add_argument("--aeads", default=",".join(AEADS_DEFAULT),
                    help=f"pipeline payload protection (default {','.join(AEADS_DEFAULT)}): " + ",".join(AEADS))
    ap.add_argument("--payload", type=int, default=51, help="pipeline payload bytes (51 = LoRaWAN DR0-DR2 max)")
    ap.add_argument("--dirs", default="up,down", help="pipeline frame directions: up (device -> network), down "
                    "(network -> device, Dir = 1); both travel through the broker")
    ap.add_argument("--suite", default="", help="TLS 1.3 cipher suite, e.g. TLS_AES_128_GCM_SHA256 (default: library's)")
    ap.add_argument("--iterations", type=int, default=None, help="connections per combination (default 50 / 3)")
    ap.add_argument("--warmup", type=int, default=None, help="unrecorded connections first (default 5 / 1)")
    ap.add_argument("--timeout", type=float, default=900, help="seconds per (library, signature) run")
    ap.add_argument("--certs", type=Path, default=ROOT / "certs")
    ap.add_argument("--mosquitto", default=shutil.which("mosquitto") or "/usr/sbin/mosquitto")
    ap.add_argument("--board", default="", help="Board column (default: detected, e.g. pi5)")
    ap.add_argument("--results-dir", type=Path, default=ROOT / "results")
    ap.add_argument("--tag", default="", help="output file suffix, e.g. pi5")
    ap.add_argument("--watch", action="store_true", help="pipeline: also run a subscriber per broker that "
                    "prints each message as received (decrypted with the shared keys); --role broker: print every "
                    "message the brokers route, from any client (no keys: a Pico's 'none' readings show as text)")
    ap.add_argument("--watch-log", type=Path, help="write the watchers' lines here instead of the terminal")
    ap.add_argument("--kex", nargs="?", const=",".join(KEX_KEMS), default="",
                    help="KEM exchange as MQTT messages through the broker (plain listener): comma list of liboqs "
                    "KEMs, X25519 or X25519MLKEM768 (the customer's TLS group), default " + ",".join(KEX_KEMS))
    ap.add_argument("--kex-n", type=int, default=50, help="--kex: exchanges per KEM")
    ap.add_argument("--kex-warmup", type=int, default=2, help="--kex: unrecorded exchanges first")
    ap.add_argument("--deploy", action="store_true",
                    help="the deployment checks against the broker's DEPLOY listeners (gen_certs.sh --deploy <broker IP>)")
    args = ap.parse_args()
    sys.stdout.reconfigure(line_buffering=True)  # keeps our lines in order with the watchers' when piped
    args.app_keys = os.urandom(96).hex() if args.watch and args.messages else ""  # + lorawan11_e2e's key
    if args.watch and not args.messages and args.role != "broker":
        raise SystemExit("--watch needs --messages N (the pipeline), or --role broker")
    args.sigs = args.sigs or SIGS_TLS  # the pipeline too: the same certificates as the Pico's
    args.iterations = args.iterations if args.iterations is not None else (3 if args.messages else 50)
    args.warmup = args.warmup if args.warmup is not None else (1 if args.messages else 5)
    args.aeads = [a.strip() for a in args.aeads.split(",") if a.strip()]
    args.dirs, args.down = [int(d.strip() == "down") for d in args.dirs.split(",") if d.strip()], 0
    bad = [a for a in args.aeads if a not in AEADS]
    if bad:
        raise SystemExit(f"unknown --aeads {bad}; choose from {AEADS}")
    norm = lambda t: re.sub(r"[^a-z0-9]", "", t.lower())
    if args.match:  # same rule as run_all.sh --algo; filters signatures and (pipeline) payload schemes
        want = [norm(m) for m in args.match.split(",")]
        sigs = [s for s in args.sigs if any(w in norm(s) for w in want)]
        aeads = [a for a in args.aeads if any(w in norm(a) for w in want)] if args.messages else []
        if not (sigs or aeads):
            raise SystemExit(f"[i] nothing matches --match {args.match}")
        args.sigs, args.aeads = sigs or args.sigs, aeads or args.aeads
    args.kex = [k.strip() for k in args.kex.split(",") if k.strip()]
    if args.match and args.kex:  # --algo also picks KEMs (e.g. mceliece)
        args.kex = [k for k in args.kex if any(w in norm(k) for w in [norm(m) for m in args.match.split(",")])] or args.kex

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))  # kill/systemd stop -> finally reaps the brokers
    broker_failed, procs, tmp = {}, [], Path(tempfile.mkdtemp(prefix="pqc-mqtt-"))
    try:
        if args.role in ("both", "broker"):
            procs, broker_failed = start_brokers(args, tmp, "127.0.0.1" if args.role == "both" else "")
            print(f"[broker] plain MQTT on :{args.base_port}; per signature mTLS / TLS listeners "
                  f"(groups {', '.join(dict.fromkeys([args.group, *SWEEP_GROUPS]))})"
                  + ("; ACL per client certificate (BROKER_ACL)" if os.environ.get("BROKER_ACL", "") not in ("", "0") else "")
                  + ":")
            for sig in args.sigs:
                print(f"  {sig:<21} :{port_of(args.base_port, sig)} / :{port_of(args.base_port, sig, 'TLS')}"
                      f"  {broker_failed.get(sig, 'up')}")
        if args.role in ("both", "broker"):
            procs += start_kem_responder(args)
        if args.role == "broker":
            if args.watch:  # every message the brokers route (a second delivery each: not during timing runs)
                procs += start_watchers(args, broker_failed)
            print(f"[broker] logs in {tmp}; each connection is shown below; Ctrl-C to stop")
            follow_logs(tmp, args)
        if args.app_keys:
            procs += start_watchers(args, broker_failed)
        out, tag = args.results_dir, f"_{args.tag}" if args.tag else ""
        if args.deploy:
            print(f"[deploy] the deployment checks against {args.host} ({args.certs}/DEPLOY*)")
            summary, raw, refused, kex, kraw = run_deploy(args)
            out.mkdir(parents=True, exist_ok=True)
            for name, rows in ((f"mqtt_mtls_summary{tag}_deploy.csv", summary), (f"mqtt_mtls_raw{tag}_deploy.csv", raw),
                               (f"deploy{tag}.csv", refused), (f"kem_exchange_summary{tag}_deploy.csv", kex),
                               (f"kem_exchange_raw{tag}_deploy.csv", kraw)):
                write_csv(out / name, rows)
            print(f"[+] wrote {out}/{{mqtt_mtls,kem_exchange}}_summary{tag}_deploy.csv, deploy{tag}.csv")
            return
        if args.kex:  # the KEM exchange instead of Stage 2 / the pipeline
            print(f"[kex] {len(args.kex)} KEMs x {args.kex_n} exchanges through {args.host}:{args.base_port}")
            summary, raw = run_kex(args)
            out.mkdir(parents=True, exist_ok=True)
            write_csv(out / f"kem_exchange_summary{tag}.csv", summary)
            write_csv(out / f"kem_exchange_raw{tag}.csv", raw)
            (out / f"kem_exchange_meta{tag}.json").write_text(json.dumps(dict(
                versions(), role=args.role, broker=f"{args.host}:{args.base_port}",
                broker_local=args.role == "both" or is_local(args.host), kems=args.kex, exchanges=args.kex_n,
                warmup=args.kex_warmup, started=time.strftime("%Y-%m-%dT%H:%M:%S%z")), indent=2))
            print(f"[+] wrote {out}/kem_exchange_{{summary,raw,meta}}{tag}")
            return
        summary, raw = run_clients(args, broker_failed)
        stem, rawname = ("pipeline", "msgs_raw") if args.messages else ("mqtt_mtls", "raw")
        out.mkdir(parents=True, exist_ok=True)
        write_csv(out / f"{stem}_summary{tag}.csv", summary)
        write_csv(out / f"{stem}_{rawname}{tag}.csv", raw)
        meta = dict(versions(), role=args.role, broker=f"{args.host}:{args.base_port}", group=args.group,
                    broker_local=args.role == "both" or is_local(args.host),
                    modes=args.modes, messages=args.messages, payload_B=args.payload, suite=args.suite or "default",
                    iterations=args.iterations, warmup=args.warmup, watch=args.watch,
                    started=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        (out / f"{stem}_meta{tag}.json").write_text(json.dumps(meta, indent=2))
        print(f"[+] wrote {out}/{stem}_{{summary,{rawname}}}{tag}.csv + {stem}_meta{tag}.json")
        if args.watch_log:
            time.sleep(0.5)  # the last deliveries
            seen = sum(1 for ln in args.watch_log.open() if " FCnt " in ln)
            sent = sum(int(s.get("msgs") or 0) for s in summary) * (args.iterations + args.warmup) // max(args.iterations, 1)
            print(f"[+] watch: independent subscribers received {seen} of {sent} messages -> {args.watch_log}")
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            p.terminate()
        shutil.rmtree(tmp, ignore_errors=True)
        if args.role in ("both", "broker"):
            broker_hs_summary(args)


if __name__ == "__main__":
    main()
