#!/usr/bin/env bash
# The gateway machine's side of the chain, in the background: the virtual gateway (the Pico's "air": UDP 1680 in,
# Semtech UDP to the Gateway Bridge on 127.0.0.1:1700) and the application: ChirpStack's uplink events from the broker
# (TLS + the login on :18935), the 256-bit layer opened, each uplink answered ("ack <FCnt>") through a relay.
#
#   BROKER=<broker ip> scripts/app.sh start | stop | restart | status | log      (log: follows app.log)
#
# Needs certs/MLDSA44/CA.crt and application.password (from the Mac), network/mqtt_tls_timer (network/build_timer.sh),
# and the device's e2e key: KEYS (default ~/.cache/iot-pqc/phase1/devices.json, the Mac's provisioning), DEVICE (default
# pico-1.1-abp). Logs in RUN_DIR (default results/testbed): vgw.log, app.log, relay.log, watch.err; app.csv at the stop.
# The broker restarts: restart this too (ChirpStack and the Gateway Bridge reconnect by themselves, this doesn't).
set -euo pipefail
cd "$(dirname "$0")/.."
D=${RUN_DIR:-results/testbed} C=certs/MLDSA44
PIDS=$D/pids
running() { [ -f $PIDS ] && for p in $(cat $PIDS); do kill -0 $p 2>/dev/null || return 1; done; }
case "${1:-}" in
    start)
        running && { echo "already running ($D)"; exit 0; }
        B=${BROKER:?BROKER=<the broker ip> (the name its certificate carries)}
        for f in $C/CA.crt $C/application.password network/mqtt_tls_timer; do [ -e $f ] || { echo "no $f"; exit 1; }; done
        E2E=$(python3 -c 'import json, os, sys
print(json.load(open(os.path.expanduser(sys.argv[1])))["devices"][sys.argv[2]]["e2e_key"])' \
            "${KEYS:-~/.cache/iot-pqc/phase1/devices.json}" "${DEVICE:-pico-1.1-abp}") || { echo "no e2e key (KEYS, DEVICE)"; exit 1; }
        for i in $(seq 60); do (exec 3<>/dev/tcp/$B/18935) 2>/dev/null && break; sleep 1; done  # at boot: the broker's Pi
        mkdir -p $D; rm -f $D/app.csv
        for f in reply events; do [ -p $D/$f.fifo ] || mkfifo $D/$f.fifo; done
        export MQTT_USER=application MQTT_PASS="$(cat $C/application.password)" CHECK_HOST=$B
        S=$(command -v setsid || true)  # Linux: their own session, so closing the SSH terminal doesn't stop them
        $S nohup python3 -u network/virtual_gateway.py --air 0.0.0.0:1680 > $D/vgw.log 2>&1 < /dev/null &
        echo $! > $PIDS
        # the application reads the watcher through a FIFO (not a pipe), so each process has its own pid to stop
        $S nohup python3 -u network/chirpstack_app.py --e2e-key "$E2E" --sent $D/vgw.log --reply $D/reply.fifo \
            --csv $D/app.csv < $D/events.fifo > $D/app.log 2>&1 &
        echo $! >> $PIDS
        RAW=1 SUB='application/+/device/+/event/up' $S nohup network/mqtt_tls_timer $B 18935 1 0 $C/CA.crt \
            > $D/events.fifo 2> $D/watch.err < /dev/null &
        echo $! >> $PIDS
        PUB=pqc/down $S nohup network/mqtt_tls_timer $B 18935 1 0 $C/CA.crt < $D/reply.fifo > $D/relay.log 2>&1 &
        echo $! >> $PIDS
        sleep 3
        if running && grep -q subscribed $D/watch.err; then echo "started, logs in $D/: $(cat $D/watch.err)"
        else echo "failed to start:"; tail -3 $D/watch.err $D/relay.log $D/app.log $D/vgw.log; "$0" stop; exit 1; fi ;;
    stop)  # the watcher first: the application reads the end of its input, prints its summary and writes app.csv
        if [ -f $PIDS ]; then
            set -- $(cat $PIDS)  # the virtual gateway, the application, the watcher, the relay
            kill ${3:-} 2>/dev/null || true
            for i in 1 2 3 4 5; do kill -0 ${2:-} 2>/dev/null || break; sleep 1; done
            kill "$@" 2>/dev/null || true; rm -f $PIDS; echo stopped
        else echo "not running"; fi ;;
    restart) "$0" stop; sleep 1; "$0" start ;;
    status) if running; then echo "running ($D)"; else echo "not running"; exit 1; fi ;;
    log) exec tail -n 50 -f $D/app.log ;;
    *) echo "usage: BROKER=<broker ip> $0 start | stop | restart | status | log"; exit 1 ;;
esac
