#!/usr/bin/env bash
# The chain's MQTT broker on the broker machine (network/mqtt_bench.py --role broker), in the background:
# ML-DSA-44 mTLS on :18835 (the Gateway Bridge, ChirpStack), TLS + the application's login on :18935, X25519MLKEM768
# only, no plain listener.
#
#   scripts/broker.sh start | stop | restart | status | log      (log: follows it; Ctrl-C stops following, not the broker)
#
# Log: results/broker.log, one line per connection (client IP, port, certificate name or login) and every error.
# CSV: results/broker_events.csv, appended across restarts: a row per message routed (sender and its listener,
# receivers, topic, bytes, the broker's own time) with the radio round trip's legs (gateway -> ChirpStack's event,
# -> the application's reply, -> ChirpStack's downlink, -> the gateway's TX ack), and a row per connection with its
# TCP accept -> MQTT CONNECT time (the mTLS or TLS handshake, then CONNECT), all on this machine's clock.
# Needs certs/MLDSA44 (README: rsync from the Mac) and a Mosquitto on OpenSSL 3.5+ (MOSQUITTO=<path> to pick one).
set -euo pipefail
cd "$(dirname "$0")/.."
PID=results/broker.pid LOG=results/broker.log
running() { [ -f $PID ] && kill -0 "$(cat $PID)" 2>/dev/null; }
case "${1:-}" in
    start)
        running && { echo "already running (pid $(cat $PID))"; exit 0; }
        mkdir -p results
        # setsid (Linux): its own session, so closing the SSH terminal that started it doesn't stop it
        $(command -v setsid || true) nohup python3 network/mqtt_bench.py --role broker \
            --mosquitto "${MOSQUITTO:-$(command -v mosquitto || echo /usr/sbin/mosquitto)}" --sigs MLDSA44 \
            --events-csv results/broker_events.csv > $LOG 2>&1 < /dev/null &
        echo $! > $PID
        sleep 3
        # a listener that didn't open (a missing certificate, a file Mosquitto can't read: run it as yourself, not
        # with sudo, which makes Mosquitto 2 drop to its own user) is printed there, but the process stays up
        if running && ! grep -q "could not start\|no certificate" $LOG; then echo "started (pid $(cat $PID)), log $LOG:"; head -4 $LOG
        else echo "failed to start:"; tail -5 $LOG; running && kill "$(cat $PID)"; rm -f $PID; exit 1; fi ;;
    stop)  # SIGTERM: mqtt_bench.py stops its Mosquitto processes too
        if running; then kill "$(cat $PID)"; rm -f $PID; echo stopped; else echo "not running"; fi ;;
    restart) "$0" stop; sleep 1; "$0" start ;;
    status) if running; then echo "running (pid $(cat $PID))"; else echo "not running"; exit 1; fi ;;
    log) exec tail -n 50 -f $LOG ;;
    *) echo "usage: $0 start | stop | restart | status | log"; exit 1 ;;
esac
