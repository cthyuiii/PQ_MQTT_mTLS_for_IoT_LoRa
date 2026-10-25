#!/usr/bin/env python3
"""The application behind ChirpStack (docs/pending.md steps 8 and 10): reads ChirpStack's uplink events, removes the
lorawan11_e2e layer (AES-256-CTR, FPort 2) that ChirpStack can't, and times ChirpStack's part of the trip.

    RAW=1 SUB='application/+/device/+/event/up' GROUP=X25519MLKEM768 network/mqtt_tls_timer 127.0.0.1 18835 1 0 \\
      certs/MLDSA44/CA.crt certs/MLDSA44/application.crt certs/MLDSA44/application.key \\
      | python3 network/chirpstack_app.py --e2e-key <64 hex> [--sent vgw.log --csv results/chirpstack_delay_<tag>.csv]
    ... | python3 network/chirpstack_app.py --e2e-master-file <file>     # per-device keys from one master key
    python3 network/chirpstack_app.py --e2e-master-file <file> --derive <DevEUI>   # provisioning: a device's key
    ... | python3 network/chirpstack_app.py ... --reply <fifo>   # the round trip: answer each uplink (see --reply)
    python3 network/chirpstack_app.py --selftest

Input: mqtt_tls_timer's RAW lines ("<unix time> <topic> <payload hex>"), each payload one ChirpStack JSON event.
FPort 1 = a lorawan11_256 reading (ChirpStack already decrypted it); FPort 2 = lorawan11_e2e: AES-256-CTR ciphertext + a
4-byte AES-256-CMAC tag, checked and decrypted here with the e2e key (APP_KEYS hex chars 192-255; the tag's key derived
from it) and blocks from the event's devAddr and fCnt, by the openssl command (no new Python dependency).
Keys: one e2e key for every device (--e2e-key, the test set-up), or per device from a master key that only the
application holds (--e2e-master-file, 64 hex): key = HKDF-SHA-256(master, "IoT-PQC lorawan11_e2e v1" | DevEUI), DevEUI
from the event. Each device is provisioned with its own key only (--derive prints it), so one device's key exposes no
other's, and ChirpStack never holds any of them. --sent: the virtual gateway's output on the same machine (same clock): delay = event received -
frame sent, per DevAddr and FCnt = ChirpStack's de-duplication wait + its processing + the MQTT hops on the way.
--reply: answer each uplink that opens with a downlink "ack <FCnt>" (FPort 1; to a lorawan11_e2e uplink, FPort 2 with
the device's 256-bit layer, its blocks on the uplink's FCnt with Dir = 1): a ChirpStack command written as a
"pub <topic> <payload>" line to a FIFO that mqtt_tls_timer's relay mode (PUB=) publishes on its own mTLS session (the
application certificate). ChirpStack sends it in the uplink's RX1 window, and the device times the round trip. With
--sent the virtual gateway's "downlink" lines give the legs at the Pi: gateway -> application, the application's own
time, application -> gateway.
"""
import argparse, base64, csv, hashlib, hmac, json, os, statistics, subprocess, sys, time

OSSL = os.environ.get("OSSL", "openssl")
E2E_LABEL = b"IoT-PQC lorawan11_e2e v1"


def hkdf_sha256(ikm, info, length=32, salt=b""):
    """RFC 5869 HKDF with SHA-256"""
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    okm, t = b"", b""
    for i in range(1, -(-length // 32) + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def device_key(master, deveui_hex):
    """a device's lorawan11_e2e key from the application's master key"""
    return hkdf_sha256(master, E2E_LABEL + bytes.fromhex(deveui_hex))


def block(first, devaddr_be, fcnt, last, down=0):
    """LoRaWAN's A_i (first 0x01) / B0 (0x49) block, as app_aead.c block(): first | 0^4 | Dir | DevAddr (LE) | FCnt (4 B LE)
    | 0 | last"""
    return bytes([first, 0, 0, 0, 0, down]) + bytes.fromhex(devaddr_be)[::-1] + fcnt.to_bytes(4, "little") + bytes([0, last])


def ossl(*args, data=b""):
    return subprocess.run([OSSL, *args], input=data, capture_output=True, check=True).stdout


def e2e_tag(key, devaddr_be, fcnt, c, down=0):
    """lorawan11_e2e's 4-byte tag: AES-256-CMAC(AES-256(key, 02|0^15) | AES-256(key, 03|0^15), B0 | ciphertext)[:4]"""
    kmac = ossl("enc", "-aes-256-ecb", "-nopad", "-K", key.hex(), data=bytes([2] + [0] * 15 + [3] + [0] * 15))
    return bytes.fromhex(ossl("mac", "-cipher", "AES-256-CBC", "-macopt", f"hexkey:{kmac.hex()}", "CMAC",
                              data=block(0x49, devaddr_be, fcnt, len(c), down) + c).decode().strip())[:4]


def e2e_open(key, devaddr_be, fcnt, data):
    """lorawan11_e2e's inner layer: ciphertext | 4-byte tag -> the reading, or None if the tag doesn't verify"""
    if len(data) < 4:
        return None
    c, tag = data[:-4], data[-4:]
    if not hmac.compare_digest(e2e_tag(key, devaddr_be, fcnt, c), tag):  # constant time
        return None
    return ctr(key, block(1, devaddr_be, fcnt, 1), c)


def e2e_seal_reply(key, devaddr_be, up_fcnt, text):
    """the reply's inner layer (Dir = 1): ciphertext | tag, its blocks on the FCnt of the uplink it answers, since
    ChirpStack picks the downlink's own FCnt only when it sends it. One reply per uplink, so a block is never reused;
    ChirpStack puts its AES-256 LoRaWAN layer and MIC around it"""
    c = ctr(key, block(1, devaddr_be, up_fcnt, 1, down=1), text)
    return c + e2e_tag(key, devaddr_be, up_fcnt, c, down=1)


def ctr(key, iv, data):
    """AES-CTR, 128 or 256 by key length. OpenSSL counts up the whole block, LoRaWAN only byte 15: the same for the
    <= 16 blocks of a LoRaWAN payload"""
    return subprocess.run([OSSL, "enc", f"-aes-{len(key) * 8}-ctr", "-K", key.hex(), "-iv", iv.hex()],
                          input=data, capture_output=True, check=True).stdout


def reading(ev, e2e_key):
    """one ChirpStack uplink event -> (devaddr, fcnt, fport, text)"""
    da, fc, fp = ev.get("devAddr", ""), int(ev.get("fCnt", 0)), int(ev.get("fPort", 0))
    data = base64.b64decode(ev.get("data", ""))
    if fp == 2:
        if not e2e_key:
            return da, fc, fp, "lorawan11_e2e ciphertext (no --e2e-key) " + data.hex()
        data = e2e_open(e2e_key, da, fc, data)
        if data is None:
            return da, fc, fp, "REJECTED: lorawan11_e2e tag doesn't verify (a wrong key, or changed after the device sealed it)"
    return da, fc, fp, data.decode(errors="replace").rstrip()


class SentLog:
    """the virtual gateway's "sent <time> DevAddr <da> FCnt <n> ..." lines, read as they are written"""
    def __init__(self, path):
        self.f, self.at = open(path), {}

    def time_of(self, da, fcnt):
        for ln in self.f:  # new lines since the last call
            w = ln.split()
            if len(w) >= 6 and w[0] == "sent" and w[2] == "DevAddr" and w[4] == "FCnt":
                self.at[(w[3], int(w[5]))] = float(w[1])
        return self.at.get((da, fcnt & 0xFFFF))  # the frame carries FCnt's low 16 bits


def reply_line(ev, fcnt, e2e_key=None):
    """--reply: the answer to one uplink event, a ChirpStack downlink command reading "ack <FCnt>", as mqtt_tls_timer's
    relay mode takes it: FPort 1, or for a lorawan11_e2e uplink (FPort 2) sealed with the device's 256-bit layer too"""
    info = ev.get("deviceInfo", {})
    eui, data, fp = info.get("devEui", ""), f"ack {fcnt}".encode(), 1
    if int(ev.get("fPort", 0)) == 2 and e2e_key:
        data, fp = e2e_seal_reply(e2e_key, ev.get("devAddr", ""), fcnt, data), 2
    cmd = {"devEui": eui, "confirmed": False, "fPort": fp, "data": base64.b64encode(data).decode()}
    return f"pub application/{info.get('applicationId', '')}/device/{eui}/command/down {json.dumps(cmd, separators=(',', ':'))}\n"


def downlinks(path):
    """the virtual gateway's "downlink <time> ... <frame hex>" lines -> [(time, DevAddr as ChirpStack shows it)]"""
    out = []
    for ln in open(path):
        w = ln.split()
        if len(w) >= 3 and w[0] == "downlink":
            f = bytes.fromhex(w[-1])
            out.append((float(w[1]), f[4:0:-1].hex()))
    return out


def legs(rows, downs):
    """down_s = the first downlink to the row's DevAddr after its reply; -> the median legs at the Pi (ms), or None"""
    for r in rows:
        r["down_s"] = next((t for t, da in downs if da == r["devaddr"] and r.get("reply_s") and t >= r["reply_s"]), None)
    ok = [r for r in rows if r["down_s"] and r["sent_s"]]
    if not ok:
        return None
    med = lambda f: statistics.median(f(r) for r in ok)
    return len(ok), med(lambda r: r["delay_ms"]), med(lambda r: (r["reply_s"] - r["recv_s"]) * 1e3), \
        med(lambda r: (r["down_s"] - r["reply_s"]) * 1e3)


def summary(rows):
    d = sorted(r["delay_ms"] for r in rows if r.get("delay_ms") is not None)
    if not d:
        return "no frame matched the --sent log"
    p95 = d[min(len(d) - 1, round(0.95 * (len(d) - 1)))]
    return (f"ChirpStack delay over {len(d)} frames: median {statistics.median(d):.1f} ms, p95 {p95:.1f} ms, "
            f"min {d[0]:.1f}, max {d[-1]:.1f}")


def selftest():
    # a lorawan11_e2e uplink sealed by app_aead.c (AppSKey 11.., e2e key 44.., DevAddr 01234567, FCnt 65, 47-byte reading)
    frame = bytes.fromhex("406745230100410002fdea0fa8b63ededba3e12842fa3adaf82853246359e6b73af42591df3b9a2fe4b87d92c18"
                          "09039f0f5ea9735cbde48ae90fc1dfbe7307b")
    assert block(1, "01234567", 65, 1) == bytes.fromhex("01000000000067452301410000000001")
    inner = ctr(bytes([0x11] * 16), block(1, "01234567", 65, 1), frame[9:-4])  # what ChirpStack does with the AppSKey
    ev = {"devAddr": "01234567", "fCnt": 65, "fPort": 2, "data": base64.b64encode(inner).decode()}
    assert reading(ev, bytes([0x44] * 32)) == ("01234567", 65, 2, '{"seq":65,"temp_c":21.5,"rh":48}')
    changed = bytes([inner[0] ^ 1]) + inner[1:]  # one bit, as whoever holds ChirpStack's keys could
    assert reading(dict(ev, data=base64.b64encode(changed).decode()), bytes([0x44] * 32))[3].startswith("REJECTED")
    assert reading(ev, None)[3].startswith("lorawan11_e2e ciphertext")
    plain = {"devAddr": "01234567", "fCnt": 1, "fPort": 1, "data": base64.b64encode(b'{"seq":1} ').decode()}
    assert reading(plain, None) == ("01234567", 1, 1, '{"seq":1}')
    # RFC 5869 test case 1 (HKDF-SHA-256), then the per-device keys: fixed by (master, DevEUI), different per device
    okm = hkdf_sha256(bytes([0x0b] * 22), bytes(range(0xf0, 0xfa)), 42, bytes(range(13)))
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")
    m = bytes(range(32))
    assert device_key(m, "e2af8c50008974f8") == device_key(m, "e2af8c50008974f8") != device_key(m, "412b55290dc583b8")
    assert len(device_key(m, "e2af8c50008974f8")) == 32
    assert summary([{"delay_ms": 210.0}, {"delay_ms": 230.0}, {"delay_ms": None}]).startswith(
        "ChirpStack delay over 2 frames: median 220.0 ms")
    ev = {"deviceInfo": {"applicationId": "a1", "devEui": "e2af8c50008974f8"}}
    topic, cmd = reply_line(ev, 878).split()[1:]
    assert topic == "application/a1/device/e2af8c50008974f8/command/down"
    assert base64.b64decode(json.loads(cmd)["data"]) == b"ack 878" and json.loads(cmd)["fPort"] == 1
    # the reply to a lorawan11_e2e uplink: the 256-bit layer on the uplink's FCnt, Dir = 1 (pinned; the Pico's
    # e2e_open_at opens these bytes in pico/tests/aead_host_test), its tag refusing another FCnt or direction
    k = bytes([0x44] * 32)
    r = e2e_seal_reply(k, "01020304", 65, b"ack 65")
    assert r.hex() == "44dc2cca568932bbe4e5", r.hex()
    assert ctr(k, block(1, "01020304", 65, 1, down=1), r[:-4]) == b"ack 65"
    assert e2e_open(k, "01020304", 65, r) is None and r[-4:] != e2e_tag(k, "01020304", 66, r[:-4], down=1)
    cmd = json.loads(reply_line(dict(ev, fPort=2, devAddr="01020304"), 65, k).split()[2])
    assert cmd["fPort"] == 2 and base64.b64decode(cmd["data"]) == r
    rs = [dict(devaddr="01234568", sent_s=10.0, recv_s=10.25, delay_ms=250.0, reply_s=10.27),
          dict(devaddr="01234568", sent_s=11.0, recv_s=11.25, delay_ms=250.0, reply_s=None)]
    n, gw_app, app, back = legs(rs, [(9.0, "01234568"), (10.6, "01234568"), (10.7, "01234569")])
    assert (n, round(gw_app), round(app), round(back)) == (1, 250, 20, 330) and rs[1]["down_s"] is None
    print("chirpstack_app selftest OK")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--e2e-key", help="lorawan11_e2e's 32-byte key, 64 hex (APP_KEYS hex chars 192-255)")
    ap.add_argument("--e2e-master-file", help="the application's master key (64 hex in a file): per-device keys")
    ap.add_argument("--derive", metavar="DEVEUI", help="with --e2e-master-file: print that device's key (64 hex), exit")
    ap.add_argument("--sent", help="the virtual gateway's output (same machine): per-frame delay")
    ap.add_argument("--csv", help="write devaddr,fcnt,fport,sent_s,recv_s,delay_ms,reading rows here")
    ap.add_argument("--reply", metavar="FIFO", help="answer each uplink: downlink commands for mqtt_tls_timer PUB= mode")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    key = bytes.fromhex(a.e2e_key) if a.e2e_key else None
    if key is not None and len(key) != 32:
        sys.exit("--e2e-key: 64 hex chars")
    master = bytes.fromhex(open(a.e2e_master_file).read().strip()) if a.e2e_master_file else None
    if master is not None and len(master) != 32:
        sys.exit("--e2e-master-file: 64 hex chars")
    if a.derive:
        if master is None:
            sys.exit("--derive needs --e2e-master-file")
        print(device_key(master, a.derive).hex())
        return
    sent, rows = SentLog(a.sent) if a.sent else None, []
    reply = open(a.reply, "w", buffering=1) if a.reply else None  # waits here until the relay opens the FIFO
    try:
        for line in sys.stdin:
            w = line.split()
            try:
                t, ev = float(w[0]), json.loads(bytes.fromhex(w[2]))
            except (IndexError, ValueError):
                continue  # not an event line
            dev_key = device_key(master, ev.get("deviceInfo", {}).get("devEui", "")) if master else key
            t0 = time.perf_counter()
            da, fc, fp, text = reading(ev, dev_key)  # FPort 2: the tag check and the AES-256 layer off
            open_ms = (time.perf_counter() - t0) * 1e3
            ts = sent.time_of(da, fc) if sent else None
            d = (t - ts) * 1e3 if ts is not None else None
            row = dict(devaddr=da, fcnt=fc, fport=fp, sent_s=ts, recv_s=t, delay_ms=d, open_ms=open_ms, reading=text)
            if reply:
                ans = fp in (1, 2) and not text.startswith("REJECTED")
                t0 = time.perf_counter()
                line = reply_line(ev, fc, dev_key) if ans else None  # FPort 2: the reply's 256-bit layer
                row["seal_ms"] = (time.perf_counter() - t0) * 1e3 if ans else None
                if ans:
                    reply.write(line)
                row["reply_s"] = time.time() if ans else None
            rows.append(row)
            print(f"recv {t:.6f} DevAddr {da} FCnt {fc} FPort {fp}" + (f" delay {d:.1f} ms" if d is not None else "")
                  + f"  {text}", flush=True)
    except KeyboardInterrupt:
        pass
    if sent:
        print(summary(rows))
    if sent and reply:
        lg = legs(rows, downlinks(a.sent))
        print(f"Round trip at the Pi over {lg[0]} replies (medians): gateway -> application {lg[1]:.1f} ms, application "
              f"{lg[2]:.1f} ms, application -> gateway {lg[3]:.1f} ms; the Pico's whole round trip: reply_us in its "
              "results" if lg else "no reply reached the gateway (is the relay running? ChirpStack's get_downlink_data_delay?)")
    if a.csv and rows:
        with open(a.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader(); w.writerows(rows)
        print(f"{len(rows)} rows -> {a.csv}")


if __name__ == "__main__":
    main()
