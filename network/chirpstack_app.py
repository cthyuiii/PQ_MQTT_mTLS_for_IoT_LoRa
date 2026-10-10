#!/usr/bin/env python3
"""The application behind ChirpStack (docs/pending.md steps 8 and 10): reads ChirpStack's uplink events, removes the
lorawan11_e2e layer (AES-256-CTR, FPort 2) that ChirpStack can't, and times ChirpStack's part of the trip.

    RAW=1 SUB='application/+/device/+/event/up' network/mqtt_tls_timer <chirpstack-host> 1884 1 0 \\
      | python3 network/chirpstack_app.py --e2e-key <64 hex> [--sent vgw.log --csv results/chirpstack_delay_<tag>.csv]
    ... | python3 network/chirpstack_app.py --e2e-master-file <file>     # per-device keys from one master key
    python3 network/chirpstack_app.py --e2e-master-file <file> --derive <DevEUI>   # provisioning: a device's key
    python3 network/chirpstack_app.py --selftest

Input: mqtt_tls_timer's RAW lines ("<unix time> <topic> <payload hex>"), each payload one ChirpStack JSON event.
FPort 1 = a lorawan11 reading (ChirpStack already decrypted it); FPort 2 = lorawan11_e2e: AES-256-CTR ciphertext + a
4-byte AES-256-CMAC tag, checked and decrypted here with the e2e key (APP_KEYS hex chars 128-191; the tag's key derived
from it) and blocks from the event's devAddr and fCnt, by the openssl command (no new Python dependency).
Keys: one e2e key for every device (--e2e-key, the test set-up), or per device from a master key that only the
application holds (--e2e-master-file, 64 hex): key = HKDF-SHA-256(master, "IoT-PQC lorawan11_e2e v1" | DevEUI), DevEUI
from the event. Each device is provisioned with its own key only (--derive prints it), so one device's key exposes no
other's, and ChirpStack never holds any of them. --sent: the virtual gateway's output on the same machine (same clock): delay = event received -
frame sent, per DevAddr and FCnt = ChirpStack's de-duplication wait + its processing + the MQTT hops on the way.
"""
import argparse, base64, csv, hashlib, hmac, json, os, statistics, subprocess, sys

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


def e2e_open(key, devaddr_be, fcnt, data):
    """lorawan11_e2e's inner layer: ciphertext | 4-byte tag -> the reading, or None if the tag doesn't verify. The tag's
    key = AES-256(key, 02|0^15) | AES-256(key, 03|0^15); tag = AES-256-CMAC(that key, B0 | ciphertext)[:4]"""
    if len(data) < 4:
        return None
    c, tag = data[:-4], data[-4:]
    kmac = ossl("enc", "-aes-256-ecb", "-nopad", "-K", key.hex(), data=bytes([2] + [0] * 15 + [3] + [0] * 15))
    mac = ossl("mac", "-cipher", "AES-256-CBC", "-macopt", f"hexkey:{kmac.hex()}", "CMAC",
               data=block(0x49, devaddr_be, fcnt, len(c)) + c).decode().strip()
    if bytes.fromhex(mac)[:4] != tag:
        return None
    return ctr(key, block(1, devaddr_be, fcnt, 1), c)


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
    print("chirpstack_app selftest OK")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--e2e-key", help="lorawan11_e2e's 32-byte key, 64 hex (APP_KEYS hex chars 128-191)")
    ap.add_argument("--e2e-master-file", help="the application's master key (64 hex in a file): per-device keys")
    ap.add_argument("--derive", metavar="DEVEUI", help="with --e2e-master-file: print that device's key (64 hex), exit")
    ap.add_argument("--sent", help="the virtual gateway's output (same machine): per-frame delay")
    ap.add_argument("--csv", help="write devaddr,fcnt,fport,sent_s,recv_s,delay_ms,reading rows here")
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
    try:
        for line in sys.stdin:
            w = line.split()
            try:
                t, ev = float(w[0]), json.loads(bytes.fromhex(w[2]))
            except (IndexError, ValueError):
                continue  # not an event line
            dev_key = device_key(master, ev.get("deviceInfo", {}).get("devEui", "")) if master else key
            da, fc, fp, text = reading(ev, dev_key)
            ts = sent.time_of(da, fc) if sent else None
            d = (t - ts) * 1e3 if ts is not None else None
            rows.append(dict(devaddr=da, fcnt=fc, fport=fp, sent_s=ts, recv_s=t, delay_ms=d, reading=text))
            print(f"recv {t:.6f} DevAddr {da} FCnt {fc} FPort {fp}" + (f" delay {d:.1f} ms" if d is not None else "")
                  + f"  {text}", flush=True)
    except KeyboardInterrupt:
        pass
    if sent:
        print(summary(rows))
    if a.csv and rows:
        with open(a.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader(); w.writerows(rows)
        print(f"{len(rows)} rows -> {a.csv}")


if __name__ == "__main__":
    main()
