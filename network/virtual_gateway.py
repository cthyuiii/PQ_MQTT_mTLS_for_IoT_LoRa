#!/usr/bin/env python3
"""Virtual LoRa gateway: hands LoRaWAN frames to a ChirpStack Gateway Bridge over the Semtech UDP packet-forwarder
protocol (v2), as if a radio gateway had received them. No radio; standard library only (docs/pending.md, step 2).

    python3 network/virtual_gateway.py --frame 40F17DBE4900020001954378762B11FF0D   # one frame, then exit
    <one frame per line, as hex> | python3 network/virtual_gateway.py               # a stream (last token per line)
    python3 network/virtual_gateway.py --selftest

Every frame goes out as channel 0 at DR0 (SF12BW125): our LoRaWAN 1.1 uplink MIC (app_aead.c, mic()) uses
TxCh = TxDr = 0, and ChirpStack recomputes them from what the gateway reports. Only uplinks are forwarded
(join request, data up). Prints the send time of each frame (for ChirpStack's delay); a downlink from ChirpStack
is printed and acknowledged (there is no radio to send it).
"""
import argparse, base64, itertools, json, os, socket, sys, threading, time

FREQ = {"as923": 923.2, "eu868": 868.1}  # channel 0 of each region, MHz
PUSH_DATA, PUSH_ACK, PULL_DATA, PULL_RESP, PULL_ACK, TX_ACK = range(6)


def packet(ident, eui, body=None):
    """version 2 | random token (2 B) | identifier | gateway EUI (8 B) | JSON"""
    return bytes([2]) + os.urandom(2) + bytes([ident]) + eui + (json.dumps(body).encode() if body is not None else b"")


def rxpk(phy, freq, t):
    return {"rxpk": [{"time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t % 1 * 1e6):06d}Z",
                      "tmst": int(t * 1e6) & 0xFFFFFFFF, "chan": 0, "rfch": 0, "freq": freq, "stat": 1,
                      "modu": "LORA", "datr": "SF12BW125", "codr": "4/5", "rssi": -60, "lsnr": 9.5,
                      "size": len(phy), "data": base64.b64encode(phy).decode()}]}


def stat(t):  # gateway statistics: ChirpStack marks the gateway as seen
    return {"stat": {"time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t)),
                     "rxnb": 0, "rxok": 0, "rxfw": 0, "ackr": 100.0, "dwnb": 0, "txnb": 0}}


def uplink(line):
    """the last token of a line, if it is a hex LoRaWAN uplink (MType join request / data up) -> bytes, else None"""
    tok = line.split()[-1] if line.split() else ""
    try:
        phy = bytes.fromhex(tok)
    except ValueError:
        return None
    return phy if len(phy) >= 12 and phy[0] >> 5 in (0, 2, 4) else None


def listen(sock, eui, sent, acked):
    while True:
        data, addr = sock.recvfrom(65535)
        if len(data) < 4:
            continue
        if data[3] == PUSH_ACK and data[1:3] in sent:
            print(f"acked {sent.pop(data[1:3])}", flush=True)
            acked.set()
        elif data[3] == PULL_RESP:
            print(f"downlink {data[4:].decode(errors='replace')}", flush=True)
            sock.sendto(bytes([2]) + data[1:3] + bytes([TX_ACK]) + eui, addr)


def keepalive(sock, eui, bridge):
    for n in itertools.count():  # forever: PULL_DATA every 10 s (downlink path), stats every 30 s
        sock.sendto(packet(PULL_DATA, eui), bridge)
        if n % 3 == 0:
            sock.sendto(packet(PUSH_DATA, eui, stat(time.time())), bridge)
        time.sleep(10)


def selftest():
    v = "40F17DBE4900020001954378762B11FF0D"  # LoRaWAN 1.0 uplink (lora-packet), also in app_aead.c's self-test
    eui = bytes.fromhex("0102030405060708")
    p = packet(PUSH_DATA, eui, rxpk(bytes.fromhex(v), 923.2, 1e9))
    assert p[0] == 2 and p[3] == PUSH_DATA and p[4:12] == eui
    r = json.loads(p[12:])["rxpk"][0]
    assert base64.b64decode(r["data"]).hex().upper() == v and r["size"] == 17
    assert (r["chan"], r["datr"], r["freq"], r["time"]) == (0, "SF12BW125", 923.2, "2001-09-09T01:46:40.000000Z")
    assert len(packet(PULL_DATA, eui)) == 12 and packet(PULL_DATA, eui)[3] == PULL_DATA
    assert uplink(f"[watch pi] 12:00:00.000001  pqc/pipe/1  17 B  {v}") == bytes.fromhex(v)
    assert uplink("60" + v[2:]) is None and uplink("not hex") is None and uplink("") is None  # downlink, text, empty
    print("virtual_gateway selftest OK")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bridge", default="127.0.0.1:1700", help="Gateway Bridge UDP address (default %(default)s)")
    ap.add_argument("--eui", default="0102030405060708", help="gateway ID as registered in ChirpStack (16 hex)")
    ap.add_argument("--region", choices=FREQ, default="as923", help="must match the Gateway Bridge and ChirpStack")
    ap.add_argument("--frame", help="send this one hex frame, wait for the bridge's ack, exit (1 = no ack)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    host, port = a.bridge.rsplit(":", 1)
    bridge, eui = (host, int(port)), bytes.fromhex(a.eui)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent, acked = {}, threading.Event()
    threading.Thread(target=listen, args=(sock, eui, sent, acked), daemon=True).start()
    threading.Thread(target=keepalive, args=(sock, eui, bridge), daemon=True).start()
    if a.frame and uplink(a.frame) is None:
        sys.exit("--frame: not a hex LoRaWAN uplink")
    for line in [a.frame] if a.frame else sys.stdin:
        phy = uplink(line)
        if phy is None:
            continue
        t = time.time()
        pkt = packet(PUSH_DATA, eui, rxpk(phy, FREQ[a.region], t))
        label = f"DevAddr {phy[4:0:-1].hex()} FCnt {phy[6] | phy[7] << 8}" if phy[0] >> 5 else "join request"
        sent[pkt[1:3]] = label
        sock.sendto(pkt, bridge)
        print(f"sent {t:.6f} {label} {len(phy)} B", flush=True)
    if a.frame:
        sys.exit(0 if acked.wait(2) else "no PUSH_ACK from the bridge at " + a.bridge)
    time.sleep(1)  # last acks


if __name__ == "__main__":
    main()
