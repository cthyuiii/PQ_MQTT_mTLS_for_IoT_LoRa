#!/usr/bin/env bash
# run_all.sh - one command for every benchmark in this repo, on macOS (Apple Silicon) or a
# Raspberry Pi (64-bit Pi OS). On the Mac it also flashes and runs the Pico W / Pico 2 W benches
# when a board is plugged in. Each stage is independent: a failure is logged, the next stage runs.
# Ends with the Stage 1 table in the customer's (Pico) form and a versions file (plan R5, R7).
#
#   ./run_all.sh                          # every stage this machine can run
#   ./run_all.sh --no-deps                # skip the brew / apt step (it installs only missing packages and
#                                         # never upgrades installed ones, so versions stay put mid-study)
#   ./run_all.sh --test pqc               # bench groups: pqc | mqtt | pipeline (comma list)
#   ./run_all.sh --lib wolfssl,liboqs     # only stages/sketches using these libraries
#   ./run_all.sh --algo ml-dsa-44,falcon  # only these algorithms (case/punctuation-insensitive)
#   ./run_all.sh --only mqtt,mtls         # pick stages by name (below)
#   ./run_all.sh --dry-run                # check prerequisites, list the stages that would run; runs nothing
#   ./run_all.sh --no-watch               # no independent subscribers in the pipeline stage
#   ./run_all.sh --quick                  # every stage with a few iterations -> *_<tag>_quick files, in minutes:
#                                         # proves the whole chain works; not numbers to report
#   TAG=pi4 ./run_all.sh                  # output suffix (default: mac on macOS, pi on Linux)
# MQTT / TLS runs count only between two machines: tls, mtls, pipeline and round3's Stage 2 run only with --broker
# (a broker on another machine of the network) and are skipped without it:
#   ./run_all.sh --serve-broker           # on the broker machine: every Stage 2 / pipeline broker,
#                                         # on all interfaces, until Ctrl-C (prints its address), with
#                                         # one line per connection (client IP, certificate, TLS / mTLS)
#   ./run_all.sh --serve-broker --watch   # + every message the brokers route (not during timing runs)
#   ./run_all.sh --broker 192.168.1.20    # on the client machine -> *_<tag>_remote files. Copy the broker
#                                         # machine's certs/ here first (same CA); --dry-run checks both
# --algo / --lib runs write *_<tag>_partial files (unless TAG is set), so a full run is never overwritten.
# Filters combine: --test pqc --lib liboqs --algo mayo = MAYO via liboqs on this host (+ Pico).
#
# Stages                                                        (--test group / --lib names)
#   openssl  Stage 1 signatures via OpenSSL EVP (+ oqs-provider)   pqc  / openssl
#   round3   Round 3 MAYO / SNOVA / MQOM / UOV: Stage 1 (OpenSSL,  pqc,mqtt / openssl,liboqs
#            liboqs) + Stage 2, oqs-provider 36cafae + liboqs main (built beside the pinned pair, which has round 2)
#   liboqs   Stage 1 signatures via liboqs 0.16, in C              pqc  / liboqs
#   wolfssl  Stage 1 via wolfSSL 5.9.4 (same C bench)              pqc / wolfssl
#   mtls     Stage 2: MQTT over plain / TLS / mutual TLS, PQ certs  mqtt / openssl,wolfssl       (--broker)
#   pipeline Full pipeline: PQ TLS/mTLS -> LoRaWAN/AES-GCM/Ascon    pipeline / openssl,wolfssl,ascon-c
#            payload -> MQTT broker -> subscriber, per message                                  (--broker)
#   tls      TLS / mTLS handshake sweep, every cert x 17 groups,   mqtt / openssl                (--broker)
#   kex      KEM exchange as MQTT messages (Classic McEliece, HQC,  mqtt / liboqs                 (--broker)
#            ML-KEM-768, X25519, X25519MLKEM768): public key out, ciphertext back via the broker's responder
#            against the broker machine's Stage 2 listeners
#   sdith faest hawk sqisign qruov   NIST reference code            pqc  / reference
#   pico     Pico sketches (macOS host)                             pqc,mqtt / pqclean, mldsa-native,
#            liboqs, liboqs-r3, wolfssl, bearssl, ascon-c, reference, rweather-crypto, openssl-goldilocks
#
# Env: OPENSSL_PREFIX (custom OpenSSL, e.g. /opt/openssl-3.5), OPENSSL_MODULES (oqs-provider dir),
#      MOSQUITTO (broker binary), MTLS_ARGS, PIPE_ARGS, PICO_ARGS, TLS_ITERS,
#      IOT_PQC_CACHE (build cache, default ~/.cache/iot-pqc)
# The whole script is one { } block: bash reads it to the end before running anything, so editing this
# file (or a git pull) during a long run can't shift the text under the running copy.
{
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NB="$HERE/signatures"
REF="$NB/reference"
NE="$HERE/network"
RESULTS="$HERE/results"
OS="$(uname)"
USER_TAG="${TAG:-}"
[ "$OS" = Darwin ] && TAG="${TAG:-mac}" || TAG="${TAG:-pi}"
NPROC="$(getconf _NPROCESSORS_ONLN)"
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
mkdir -p "$RESULTS"

ONLY="all" DEPS=1 TESTS="" LIBS="" ALGOS="" DRY=0 QUICK=0 WATCH=1 BROKER="" SERVE=0 BWATCH=0
while [ $# -gt 0 ]; do
    case "$1" in
        --broker)  BROKER="$2"; shift ;;
        --serve-broker) SERVE=1 ;;
        --no-deps) DEPS=0 ;;
        --only)    ONLY="$2"; shift ;;
        --test)    TESTS="$2"; shift ;;
        --lib)     LIBS="$2"; shift ;;
        --algo)    ALGOS="$2"; shift ;;
        --dry-run) DRY=1; DEPS=0 ;;
        --quick)   QUICK=1 ;;
        --no-watch) WATCH=0 ;;
        --watch)   BWATCH=1 ;;   # with --serve-broker: also print every message the brokers route
        *) echo "unknown arg: $1 (see the header of $0)"; exit 1 ;;
    esac
    shift
done
# a filtered run must not overwrite a full run's files: write *_<tag>_partial unless TAG was given
[ -z "$USER_TAG" ] && [ -n "$ALGOS$LIBS" ] && TAG="${TAG}_partial"
[ -z "$USER_TAG" ] && [ "$QUICK" = 1 ] && TAG="${TAG}_quick"
[ -z "$USER_TAG" ] && [ -n "$BROKER" ] && TAG="${TAG}_remote"   # LAN round trips: not comparable with loopback
SIG_N=${SIG_N:-100}   # Stage 1 iterations: the same for every algorithm and library (OpenSSL, liboqs, wolfSSL, reference)
if [ "$QUICK" = 1 ]; then  # a few iterations everywhere; any of these can still be set by hand
    : "${TLS_ITERS:=20}" "${PIPE_MSGS:=20}" "${MTLS_ARGS:=--iterations 5 --warmup 1}" "${KEX_N:=5}"
    : "${PICO_ARGS:=--match ml-dsa-44}"
    SIG_N=5
fi
log()  { printf '\n=== %s ===\n' "$*"; }
norm() { printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9,|'; }
# has FILTER VALUES: empty filter, or some filter item is a substring of some value (normalized, comma lists)
has() {
    [ -z "$1" ] && return 0
    local f v
    for f in $(norm "$1" | tr ',' ' '); do
        for v in $(norm "$2" | tr ',|' '  '); do case "$v" in *"$f"*) return 0 ;; esac; done
    done
    return 1
}
# stage NAME TESTS LIBS: selected by --only, --test and --lib? (--dry-run: print it and run nothing)
stage() {
    { [ "$ONLY" = all ] || echo ",$ONLY," | grep -qi ",$1,"; } && has "$TESTS" "$2" && has "$LIBS" "$3" || return 1
    if [ "$QUICK" = 1 ] && [ "$3" = reference ] && [ "$ONLY" = all ] && [ -z "$LIBS" ]; then
        echo "[i] --quick: $1 skipped (NIST reference builds take long; add --lib reference to include)"; return 1
    fi
    [ "$DRY" = 1 ] && { printf '  would run: %-9s (--test %s; libraries: %s)\n' "$1" "$2" "$3"; return 1; }
    return 0
}
# pick ITEM... : the items whose name or |alias matches --algo (spec part printed)
pick() { local i; for i in "$@"; do has "$ALGOS" "$i" && printf '%s\n' "${i%%|*}"; done; }
CACHE="${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}"

# ---------------------------------------------------------------- 0. deps --
if [ "$DEPS" = 1 ]; then
    if [ "$OS" = Darwin ]; then
        log "installing build deps (brew)"
        command -v brew >/dev/null || { echo "[-] Homebrew required: https://brew.sh"; exit 1; }
        # plain `brew install` upgrades outdated formulae (man brew): that would change versions mid-study
        HOMEBREW_NO_INSTALL_UPGRADE=1 HOMEBREW_NO_AUTO_UPDATE=1 \
            brew install openssl@3 cmake mosquitto autoconf automake libtool arduino-cli \
            || echo "[!] brew install failed - continuing, individual stages may break"
    else
        log "installing build deps (apt)"
        sudo apt-get update -qq || true
        sudo apt-get install -y --no-upgrade build-essential cmake libssl-dev python3 python3-venv unzip wget curl \
            git autoconf automake libtool mosquitto mosquitto-clients \
            || echo "[!] apt failed - continuing, individual stages may break"
    fi
fi
python3 -c "import serial" 2>/dev/null \
    || echo "[!] pyserial missing (Pico runner): activate the venv and pip install -r requirements.txt"

# ------------------------------------------------------- platform set-up --
MHZ_ARG=()
if [ -r /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq ]; then
    MHZ_ARG=(--cpu-mhz $(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq) / 1000 )))
fi
# PQ TLS needs OpenSSL >= 3.5: Homebrew's openssl@3 on macOS, the system one on Pi OS Trixie,
# or OPENSSL_PREFIX (e.g. the customer's /opt/openssl-3.5) anywhere else.
[ "$OS" = Darwin ] && OPENSSL_PREFIX="${OPENSSL_PREFIX:-$(brew --prefix openssl@3 2>/dev/null)}"
OSSL_FLAGS="-lssl -lcrypto"
if [ -n "${OPENSSL_PREFIX:-}" ]; then
    OSSL_FLAGS="-I$OPENSSL_PREFIX/include"
    for d in lib lib64; do
        [ -d "$OPENSSL_PREFIX/$d" ] && OSSL_FLAGS="$OSSL_FLAGS -L$OPENSSL_PREFIX/$d -Wl,-rpath,$OPENSSL_PREFIX/$d"
    done
    OSSL_FLAGS="$OSSL_FLAGS -lssl -lcrypto"
    export OSSL="$OPENSSL_PREFIX/bin/openssl" OPENSSL_PREFIX
    export CPATH="$OPENSSL_PREFIX/include${CPATH:+:$CPATH}"            # reference builds link -lcrypto
    export LIBRARY_PATH="$OPENSSL_PREFIX/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
fi
# oqs-provider (Falcon/MAYO/SNOVA inside OpenSSL), if built in ./oqs-provider (README §3.1)
for d in "$HERE/oqs-provider/_build/lib" "$HERE/oqs-provider/build/lib"; do
    [ -z "${OPENSSL_MODULES:-}" ] && ls "$d"/oqsprovider.* >/dev/null 2>&1 && export OPENSSL_MODULES="$d"
done
MOSQ="${MOSQUITTO:-$(command -v mosquitto || echo /usr/sbin/mosquitto)}"
BOARD=$(python3 -c "import sys; sys.path.insert(0, '$NE'); from provenance import board_name; print(board_name())" 2>/dev/null || echo "$TAG")
echo "[i] $OS / $BOARD, tag=$TAG | $(${OSSL:-openssl} version) | oqsprovider: ${OPENSSL_MODULES:-not found}"

# round 3 MAYO / SNOVA / MQOM (round3 stage, --serve-broker): oqs-provider 36cafae needs liboqs main, so that
# pair is built in the cache beside the pinned one; OpenSSL loads it only where OPENSSL_MODULES points at it
R3_LIBOQS=b196b57a R3_PROV=36cafae R3_MODULES="$CACHE/oqs-provider-r3-build/lib"
R3_CERTS="MAYO1:mayo1 MAYO2:mayo2 MAYO3:mayo3 MAYO5:mayo5 SNOVA1B:snova1b SNOVA1K:snova1k SNOVA1S:snova1s
    SNOVA3B:snova3b SNOVA3K:snova3k SNOVA3S:snova3s SNOVA5B:snova5b SNOVA5K:snova5k SNOVA5S:snova5s"
R3_LABELS=$(for p in $R3_CERTS; do printf '%s ' "${p%%:*}"; done)
r3_build() {  # once (a few minutes); later runs reuse it
    ls "$R3_MODULES"/oqsprovider.* >/dev/null 2>&1 && return 0
    echo "[i] building liboqs $R3_LIBOQS + oqs-provider $R3_PROV (round 3) in $CACHE (once: a few minutes on a Mac, ~25-40 min on a Pi 4, ~10-15 on a Pi 5; silent)"
    local r s
    for r in "liboqs:$R3_LIBOQS" "oqs-provider:$R3_PROV"; do
        s="$CACHE/${r%%:*}-r3-src"
        { [ -d "$s" ] || git clone -q "https://github.com/open-quantum-safe/${r%%:*}.git" "$s"; } \
            && git -C "$s" checkout -q "${r#*:}" || return 1
    done
    cmake -S "$CACHE/liboqs-r3-src" -B "$CACHE/liboqs-r3-build" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DCMAKE_INSTALL_PREFIX="$CACHE/liboqs-r3" >/dev/null \
        && cmake --build "$CACHE/liboqs-r3-build" -j"$NPROC" --target install >/dev/null \
        && cmake -S "$CACHE/oqs-provider-r3-src" -B "$CACHE/oqs-provider-r3-build" -DCMAKE_BUILD_TYPE=Release \
            ${OPENSSL_PREFIX:+-DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX"} -Dliboqs_DIR="$CACHE/liboqs-r3/lib/cmake/liboqs" \
            >/dev/null && cmake --build "$CACHE/oqs-provider-r3-build" -j"$NPROC" >/dev/null
}
# certs/ for TLS. With --broker they must be the broker machine's (same CA), so they are never made here.
need_certs() {  # need_certs DIR [gen_certs.sh env...]
    local d=$1; shift
    ls "$d"/*/client.crt >/dev/null 2>&1 && return 0
    [ -n "$BROKER" ] && { echo "[!] no $d: copy the broker machine's certs/ here (README 0.1: rsync -a --delete, run on the Mac)"; return 1; }
    (cd "$HERE" && env "$@" bash scripts/gen_certs.sh) || { echo "[!] gen_certs.sh failed"; return 1; }
}
r3_certs() { need_certs "$HERE/certs/round3" OPENSSL_MODULES="$R3_MODULES" CERTS_DIR=certs/round3 OQS_SIGS="$R3_CERTS"; }
# liboqs 0.16 for this machine (the liboqs stage, and the KEM exchange: the kex client and --serve-broker's responder)
liboqs_host() {
    [ -f "$CACHE/liboqs-host/include/oqs/oqs.h" ] && return 0
    echo "[i] building liboqs 0.16.0 for this machine in $CACHE (once: a few minutes on a Mac, ~25-40 min on a Pi 4, ~10-15 on a Pi 5; silent)"
    [ -d "$CACHE/liboqs-src" ] || git clone -q --depth 1 --branch 0.16.0 \
        https://github.com/open-quantum-safe/liboqs.git "$CACHE/liboqs-src"
    cmake -Wno-dev -S "$CACHE/liboqs-src" -B "$CACHE/liboqs-build-host" -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF \
        -DCMAKE_INSTALL_PREFIX="$CACHE/liboqs-host" >/dev/null && cmake --build "$CACHE/liboqs-build-host" -j"$NPROC" \
        --target install >/dev/null || { echo "[!] host liboqs build failed"; return 1; }
}
# the pinned oqs-provider (on liboqs 0.16.0) on every machine: client and broker must agree on algorithms, TLS group
# names and codepoints. A machine whose provider is another build (e.g. an older system-wide one) gets this one,
# built once in the cache and used through OPENSSL_MODULES.
PROV=c174ed7
prov_pinned() {
    ${OSSL:-openssl} list -providers -verbose -provider oqsprovider 2>/dev/null | grep -q "($PROV)" && return 0
    local s="$CACHE/oqs-provider-src" b="$CACHE/oqs-provider-build"
    if ! ls "$b"/lib/oqsprovider.* >/dev/null 2>&1; then
        liboqs_host || return 1
        echo "[i] building oqs-provider $PROV on liboqs 0.16.0 in $CACHE (once: ~5 min on a Pi; silent)"
        { [ -d "$s" ] || git clone -q https://github.com/open-quantum-safe/oqs-provider.git "$s"; } \
            && git -C "$s" checkout -q "$PROV" \
            && cmake -S "$s" -B "$b" -DCMAKE_BUILD_TYPE=Release ${OPENSSL_PREFIX:+-DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX"} \
                -Dliboqs_DIR="$(ls -d "$CACHE"/liboqs-host/lib*/cmake/liboqs | head -1)" >/dev/null \
            && cmake --build "$b" -j"$NPROC" >/dev/null || { echo "[!] oqs-provider $PROV build failed"; return 1; }
    fi
    export OPENSSL_MODULES="$b/lib"
    echo "[i] oqs-provider $PROV from $OPENSSL_MODULES (the one this machine had is another build)"
}
# the OpenSSL MQTT client (with liboqs when installed): the KEM responder, --watch subscribers, mtls / pipeline / tls / kex
timer() { bash "$NE/build_ascon.sh" >/dev/null 2>&1; bash "$NE/build_timer.sh" openssl || echo "[!] mqtt_tls_timer build failed" >&2; }
save_versions() { python3 -c "import sys, json; sys.path.insert(0, '$NE'); from provenance import versions; print(json.dumps(versions(), indent=2))" \
    > "$RESULTS/versions_$1.json" && echo "[+] wrote $RESULTS/versions_$1.json"; }

[ "$DRY" = 1 ] || prov_pinned || echo "[!] no oqs-provider $PROV: Falcon / MAYO / SNOVA rows and the oqs-provider groups may fail"

# ------------------------------- the broker machine of --broker runs (--serve-broker) --
if [ "$SERVE" = 1 ]; then
    log "brokers for ./run_all.sh --broker: plain :18830, TLS / mTLS per signature (round 3 from :20830), all interfaces"
    need_certs "$HERE/certs"
    # the timer: the KEM exchange's responder (always) and the --watch subscribers
    liboqs_host; timer >/dev/null
    BW=(); [ "$BWATCH" = 1 ] && BW=(--watch)
    # each connection is printed here as it arrives; --watch adds every message (a second delivery: not for timing runs)
    python3 "$NE/mqtt_bench.py" --role broker --mosquitto "$MOSQ" ${BW[@]+"${BW[@]}"} & BPIDS=$!
    if r3_build && r3_certs; then
        OPENSSL_MODULES="$R3_MODULES" python3 "$NE/mqtt_bench.py" --role broker --mosquitto "$MOSQ" \
            --base-port 20830 --certs "$HERE/certs/round3" --sigs $R3_LABELS ${BW[@]+"${BW[@]}"} & BPIDS="$BPIDS $!"
    else
        echo "[!] round 3 provider build failed: no round 3 brokers"
    fi
    save_versions "${TAG}_broker"   # this machine's Mosquitto / OpenSSL / providers
    IP=$(python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(('192.0.2.1', 9)); print(s.getsockname()[0])" 2>/dev/null)
    sleep 3
    echo "[i] give the client this machine's certs/ (README 0.1), e.g. from the Mac's repo root:"
    echo "      rsync -a --delete certs/ <pi-user>@<pi-ip>:PQ_MQTT_mTLS_for_IoT_LoRa/certs/   (Pi broker: swap the two paths)"
    echo "    then ./run_all.sh --broker ${IP:-<this-machine-IP>}   (Ctrl-C here stops the brokers)"
    trap 'kill $BPIDS 2>/dev/null' INT TERM
    wait
    exit 0
fi
RB=() REACH=1   # --broker: MQTT stages connect to that machine's brokers instead of starting their own
if [ -n "$BROKER" ]; then
    RB=(--role client --host "$BROKER")
    python3 -c "import socket; socket.create_connection(('$BROKER', 18830), 3)" 2>/dev/null \
        || { REACH=0; echo "[!] broker $BROKER:18830 unreachable: is that the broker machine's current IP (Mac: ipconfig getifaddr en0), on this network, running ./run_all.sh --serve-broker? MQTT stages are skipped"; }
    python3 -c "import socket; socket.socket().bind(('$BROKER', 0))" 2>/dev/null \
        && echo "[!] $BROKER is this machine: the MQTT stages run, but all_results.csv won't count them"
fi
# certs/ must be the broker machine's (same CA, keys readable): else every TLS / mTLS run fails
CERTS_OK=1
if [ -n "$BROKER" ] && [ "$REACH" = 1 ] && ls "$HERE"/certs/*/client.crt >/dev/null 2>&1; then
    P=$(cd "$NE" && python3 -c "from mqtt_bench import port_of; print(port_of(18830, 'ECDSAP256', 'TLS'))")
    ${OSSL:-openssl} s_client -connect "$BROKER:$P" -CAfile "$HERE/certs/ECDSAP256/CA.crt" -verify_return_error \
        </dev/null >/dev/null 2>&1 || { CERTS_OK=0
        echo "[!] certs/ here is not $BROKER's: its TLS listener :$P does not verify against certs/ECDSAP256/CA.crt."
        echo "    On the broker machine, from the repo root: rsync -a --delete certs/ <user>@<this-machine>:<repo>/certs/"; }
    for k in "$HERE"/certs/*/client.key; do
        [ -r "$k" ] || { CERTS_OK=0; echo "[!] $k is not readable by $(id -un) (made with sudo?): sudo chown -R $(id -un) \"$HERE/certs\""; break; }
    done
fi
# a Pico on USB: its serial port, or its BOOTSEL drive (existence tests: no ls, which fails on a missing path)
pico_present() { compgen -G "/dev/cu.usbmodem*" >/dev/null || [ -d /Volumes/RPI-RP2 ] || [ -d /Volumes/RP2350 ]; }
need_broker() {  # need_broker STAGE [plain]: MQTT results count only between two machines; TLS needs the broker's certs
    [ -n "$BROKER" ] || { echo "[i] $1: skipped - MQTT runs count only against a broker on another machine (--broker IP, README 0.1)"; return 1; }
    [ "$REACH" = 1 ] || { echo "[i] $1: skipped - broker $BROKER:18830 unreachable (the [!] line at the start: wrong IP, another network?)"; return 1; }
    [ "$CERTS_OK" = 1 ] || [ "${2:-}" = plain ] || { echo "[i] $1: skipped - certs/ is not the broker's (the [!] lines above)"; return 1; }
    return 0
}

if [ "$DRY" = 1 ]; then  # prerequisites; the stage list follows as each stage is reached
    log "dry run: prerequisites (nothing is built or measured)"
    chk() { if (eval "$2") >/dev/null 2>&1; then echo "  [ok] $1"; else echo "  [--] $1  ->  $3"; fi; }
    OV=$(${OSSL:-openssl} version 2>/dev/null | cut -d' ' -f2)
    chk "OpenSSL >= 3.5: ${OV:-not found}" 'case "$OV" in 3.[5-9]*|3.[1-9][0-9]*|[4-9].*) true ;; *) false ;; esac' \
        "brew install openssl@3, or OPENSSL_PREFIX=/path/to/openssl-3.5"
    chk "oqs-provider: ${OPENSSL_MODULES:-not found}" '[ -n "${OPENSSL_MODULES:-}" ]' \
        "optional (Falcon/MAYO/SNOVA in OpenSSL): build it as in README section 0"
    # the provider OpenSSL loads must be the source checked out (a pull without a rebuild splits them)
    PB=$(${OSSL:-openssl} list -providers -verbose -provider oqsprovider 2>/dev/null | grep -o 'v\.[^ ]* ([0-9a-f]*)' | head -1)
    chk "oqs-provider = $PROV, the broker's (found: ${PB:-none})" 'case "$PB" in *"($PROV)"*) true ;; *) ls "$CACHE"/oqs-provider-build/lib/oqsprovider.* ;; esac' \
        "built in $CACHE on the first real run (~5 min on a Pi)"
    chk "round 3 oqs-provider $R3_PROV + liboqs $R3_LIBOQS (round3 stage)" 'ls "$R3_MODULES"/oqsprovider.*' \
        "built by the round3 stage on first use (a few minutes)"
    if [ -n "$BROKER" ]; then  # --broker: the other machine must be serving, with the same certs/ (CA)
        chk "broker $BROKER:18830 reachable" '[ "$REACH" = 1 ]' "./run_all.sh --serve-broker on $BROKER; allow incoming connections there"
        [ "$REACH" = 1 ] && chk "certs/ = the broker's (same CA, keys readable)" '[ "$CERTS_OK" = 1 ]' \
            "copy the broker machine's certs/ here (README 0.1: rsync -a --delete, run on the Mac)"
    fi
    chk "C compiler" 'command -v cc' "xcode-select --install / apt install build-essential"
    chk "cmake, autoconf, libtool (liboqs, wolfSSL)" 'command -v cmake && command -v autoreconf && { command -v libtoolize || command -v glibtoolize; }' \
        "brew install cmake autoconf automake libtool"
    chk "Mosquitto: $MOSQ" '[ -x "$MOSQ" ]' "brew install mosquitto / apt install mosquitto"
    chk "--broker IP (tls, mtls, pipeline, kex, round3 Stage 2)" '[ -n "$BROKER" ]' \
        "without it they are skipped: ./run_all.sh --serve-broker on another machine, then --broker <its IP> here"
    chk "Python packages (pyserial for the Pico runner)" 'python3 -c "import serial"' \
        "source .venv/bin/activate && pip install -r requirements.txt"
    chk "client certificates in certs/" 'ls "$HERE"/certs/*/client.crt' "made by gen_certs.sh when the mtls stage starts"
    chk "arduino-cli + rp2040 core (pico stage)" 'arduino-cli core list | grep -q "rp2040:rp2040"' "README section 0, Pico"
    chk "a Pico plugged in" 'pico_present' "the pico stage is skipped without one"
    chk "qemu-system-arm (pico/tests/qemu_liboqs)" 'command -v qemu-system-arm' "optional: brew install qemu"
    log "dry run: stages (in order)"
fi

# --------------------------------------------------- 1. Stage 1: OpenSSL --
# the customer's set: classical baselines, ML-DSA, Falcon, SLH-DSA ("spec|friendly name" so --algo matches either).
# The NIST additional candidates OpenSSL reaches via oqs-provider (MAYO, SNOVA, MQOM) run in round3: their round 3 sets.
OSSL_SIGS=$(pick "RSA:2048|RSA-2048" "RSA:3072|RSA-3072" "EC:P-256|ECDSA-P256" "ED25519" \
    ML-DSA-44 ML-DSA-65 ML-DSA-87 "falcon512|Falcon-512" "falcon1024|Falcon-1024" \
    SLH-DSA-SHA2-128f SLH-DSA-SHAKE-128f SLH-DSA-SHA2-192f SLH-DSA-SHAKE-192f SLH-DSA-SHA2-256f \
    SLH-DSA-SHAKE-256f \
    SLH-DSA-SHA2-128s SLH-DSA-SHAKE-128s SLH-DSA-SHA2-192s SLH-DSA-SHAKE-192s SLH-DSA-SHA2-256s SLH-DSA-SHAKE-256s)
# sig_speed: sig_speed.c built for OpenSSL, liboqs or wolfSSL; one call per algorithm (the terminal
# shows progress), SIG_N iterations each. Real cycles: perf on Linux (paranoid <= 2), kperf on macOS (needs
# sudo); else cycles = 0.
sig_speed() {  # sig_speed PROGRAM OUT SPEC...
    local prog=$1 out=$2 i=0 n t0 spec; shift 2
    sudo -n sysctl -w kernel.perf_event_paranoid=1 >/dev/null 2>&1 || true
    echo "algo,op,n,mean_ms,mean_cycles,median_ms,std_ms,median_cycles,min_ms,max_ms,ops_s" > "$out.csv"; : > "$out.meta"
    for spec; do
        i=$((i + 1)) n=$SIG_N t0=$SECONDS
        printf '  [%2d/%d] %-22s %4s iterations ... ' "$i" "$#" "$spec" "$n"
        "$prog" "$n" "$spec" 2>> "$out.meta" | tail -n +2 >> "$out.csv"
        rc=${PIPESTATUS[0]}   # a crash is a result: it goes in the Stage 1 table as its status
        [ "$rc" -gt 128 ] && echo "#meta algo=$spec status=CRASH(SIG$(kill -l $((rc - 128)) 2>/dev/null || echo $((rc - 128))))" >> "$out.meta"
        echo "$((SECONDS - t0)) s"
    done
    echo "[+] wrote $out.csv (+ .meta: sizes, unsupported algorithms)"
}
ossl_speed() { cc -O2 "$NB/sig_speed.c" -o "$NB/openssl_sig_speed" $OSSL_FLAGS -lm || { echo "[!] openssl_sig_speed build failed"; return 1; }; }
oqs_speed() {  # oqs_speed LIBOQS_PREFIX OUT SPEC...: the same timing code built on that liboqs install
    local lq=$1 out=$2; shift 2
    if cc -O2 -DSIG_LIBOQS "$NB/sig_speed.c" -o "$NB/liboqs_sig_speed" -I"$lq/include" \
            -L"$lq/lib" -L"$lq/lib64" -Wl,-rpath,"$lq/lib" -Wl,-rpath,"$lq/lib64" -loqs -lm; then
        sig_speed "$NB/liboqs_sig_speed" "$out" "$@"
    else
        echo "[!] liboqs_sig_speed build failed"
    fi
}
if stage openssl pqc openssl && [ -n "$OSSL_SIGS" ]; then
    log "openssl_sig_speed (EVP keygen/sign/verify, per-op stats, sizes, cycles)"
    ossl_speed && sig_speed "$NB/openssl_sig_speed" "$RESULTS/openssl_sig_speed_$TAG" $OSSL_SIGS
fi

# ------------ 1r. Round 3 MAYO / SNOVA / MQOM / UOV (oqs-provider 36cafae + liboqs main) --
# Stage 1 (OpenSSL and liboqs directly) and Stage 2 (MQTT over mTLS, certs/round3) for the NIST round 3 parameter sets.
# The pinned pair (oqs-provider c174ed7 + liboqs 0.16.0) has only the round 2 sets, which round 3 replaced (MAYO-1/2,
# UOV-Ip/III/V sizes; new SNOVA sets; MQOM v3). liboqs main is also the Pico's round 3 library (LIBOQS_ROUND=3).
R3_SIGS=$(pick "mayo1|MAYO-1" "mayo2|MAYO-2" "mayo3|MAYO-3" "mayo5|MAYO-5" "snova1b|SNOVA_I_B" "snova1k|SNOVA_I_K" \
    "snova1s|SNOVA_I_S" "snova3b|SNOVA_III_B" "snova3k|SNOVA_III_K" "snova3s|SNOVA_III_S" "snova5b|SNOVA_V_B" \
    "snova5k|SNOVA_V_K" "snova5s|SNOVA_V_S" "mqom3cat1gf16fastct|mqom3_cat1" "mqom3cat3gf16fastct|mqom3_cat3" \
    "mqom3cat5gf16fastct|mqom3_cat5")
R3_OQS_SIGS=$(pick MAYO-1 MAYO-2 MAYO-3 MAYO-5 $(for l in I III V; do for v in K B S; do echo "SNOVA_${l}_$v"; done; done) \
    $(for c in 1 3 5; do for p in gf16_fast_ct gf16_short_ct gf2_shorter_ct; do echo "mqom3_cat${c}_$p"; done; done) \
    $(for v in Is Ip III V; do for k in "" -pkc -pkc-skc; do echo "OV-$v$k|UOV-$v$k"; done; done))
if stage round3 "pqc,mqtt" openssl,liboqs && [ -n "$R3_SIGS$R3_OQS_SIGS" ]; then
    log "Round 3 MAYO / SNOVA / MQOM / UOV: oqs-provider $R3_PROV + liboqs main $R3_LIBOQS"
    if r3_build; then
        (export OPENSSL_MODULES="$R3_MODULES"
        save_versions "${TAG}_r3"
        if has "$TESTS" pqc; then
            has "$LIBS" openssl && [ -n "$R3_SIGS" ] && ossl_speed \
                && sig_speed "$NB/openssl_sig_speed" "$RESULTS/openssl_sig_speed_r3_$TAG" $R3_SIGS
            has "$LIBS" liboqs && [ -n "$R3_OQS_SIGS" ] && oqs_speed "$CACHE/liboqs-r3" "$RESULTS/liboqs_sig_speed_r3_$TAG" $R3_OQS_SIGS
        fi
        if has "$TESTS" mqtt && has "$LIBS" openssl && need_broker "round3 Stage 2" && r3_certs; then   # wolfSSL has no MAYO / SNOVA: OpenSSL client only
            timer >/dev/null
            python3 "$NE/mqtt_bench.py" --results-dir "$RESULTS" --tag "${TAG}_r3" --board "$BOARD" \
                --mosquitto "$MOSQ" --clients openssl --base-port 20830 --certs "$HERE/certs/round3" --sigs $R3_LABELS \
                ${ALGOS:+--match "$ALGOS"} ${RB[@]+"${RB[@]}"} ${MTLS_ARGS:-} \
                || echo "[!] round 3 Stage 2 failed (or nothing matched --algo)"
        fi)
    else
        echo "[!] round 3 build failed: see $CACHE/liboqs-r3-build and $CACHE/oqs-provider-r3-build"
    fi
fi

# --------------------------------------- 1a. Stage 1: liboqs 0.16, in C --
# the same timing code as the openssl stage (sig_speed.c built with -DSIG_LIBOQS), on the liboqs
# release the Pico runs; liboqs names, "name|friendly name" so --algo matches either
LIBOQS_SIGS=$(pick ML-DSA-44 ML-DSA-65 ML-DSA-87 Falcon-512 Falcon-1024 Falcon-padded-512 Falcon-padded-1024 \
    $(for h in SHA2 SHAKE; do for n in 128 192 256; do for x in F S; do
        echo "SLH_DSA_PURE_${h}_$n$x|SLH-DSA-$h-$n$(echo $x | tr FS fs)"; done; done; done))
if stage liboqs pqc liboqs && [ -n "$LIBOQS_SIGS" ]; then
    log "liboqs 0.16 directly, in C (same timing code as the openssl stage, same liboqs release as the Pico)"
    liboqs_host && oqs_speed "$CACHE/liboqs-host" "$RESULTS/liboqs_sig_speed_$TAG" $LIBOQS_SIGS
fi

# --------------------------------------------------- 1b. Stage 1: wolfSSL --
# signatures: sig_speed.c built on wolfCrypt (-DSIG_WOLFSSL), Stage 1 names. The build is also the Stage 2
# wolfSSL client's. Only signatures run on one machine: TLS, key exchange and LoRaWAN / AES / Ascon messages are
# measured through the MQTT broker (tls, mtls, pipeline).
WOLF_SIGS=$(pick RSA-2048 RSA-3072 ECDSA-P256 Ed25519 ML-DSA-44 ML-DSA-65 ML-DSA-87 Falcon-512 Falcon-1024 \
    $(for h in SHA2 SHAKE; do for n in 128 192 256; do for x in f s; do echo "SLH-DSA-$h-$n$x"; done; done; done))
if stage wolfssl pqc wolfssl && [ -n "$WOLF_SIGS" ]; then
    log "wolfSSL 5.9.4 (ML-DSA/SLH-DSA/Falcon/RSA/ECDSA/Ed25519): build, bench"
    if bash "$NE/build_wolfssl.sh"; then
        W="${WOLFSSL_PREFIX:-$CACHE/wolfssl-install}"
        cc -O2 -DSIG_WOLFSSL "$NB/sig_speed.c" -o "$NB/wolfssl_sig_speed" -I"$W/include" -L"$W/lib" \
            -Wl,-rpath,"$W/lib" -lwolfssl -lm && sig_speed "$NB/wolfssl_sig_speed" "$RESULTS/wolfssl_sig_speed_$TAG" $WOLF_SIGS \
            || echo "[!] wolfssl_sig_speed build failed"
    else
        echo "[!] wolfSSL build failed (needs autoconf automake libtool; see build_wolfssl.sh)"
    fi
fi

# the wolfSSL client of mtls / pipeline, rebuilt from the current code (its handshake crypto timing, README 83): once
# wolfSSL is built, build_wolfssl.sh only relinks the client (its stamp skips an unchanged library)
wolf_client() {
    [ -n "${WOLF_CLIENT_DONE:-}" ] && return 0
    WOLF_CLIENT_DONE=1
    bash "$NE/build_wolfssl.sh" >/dev/null 2>&1 || echo "[i] wolfSSL client not rebuilt (build_wolfssl.sh failed): the existing one runs"
    [ -x "$NE/mqtt_tls_timer_wolfssl" ] || echo "[i] no wolfSSL client (run the wolfssl stage) - OpenSSL rows only"
}

# ------------------ 2. Stage 2: MQTT over mutual TLS with PQ certificates --
if stage mtls mqtt "openssl,wolfssl" && need_broker mtls; then
    log "Stage 2: MQTT over mTLS, PQ certs, X25519MLKEM768 fixed; OpenSSL + wolfSSL clients"
    timer; wolf_client
    need_certs "$HERE/certs"
    python3 "$NE/mqtt_bench.py" --results-dir "$RESULTS" --tag "$TAG" --board "$BOARD" \
        --mosquitto "$MOSQ" ${ALGOS:+--match "$ALGOS"} ${LIBS:+--clients "$LIBS"} ${RB[@]+"${RB[@]}"} ${MTLS_ARGS:-} \
        || echo "[!] mTLS MQTT bench failed (or nothing matched --algo / --lib)"
fi

# ---- 2b. Full pipeline: PQ handshake -> payload AEAD -> MQTT broker -> subscriber --
if stage pipeline pipeline "openssl,wolfssl,ascon-c" && need_broker pipeline; then
    log "Full pipeline: PQ TLS/mTLS handshake -> LoRaWAN / AES-GCM / Ascon payload -> broker -> subscriber"
    timer; wolf_client
    need_certs "$HERE/certs"
    W=(); [ "$WATCH" = 1 ] && W=(--watch --watch-log "$RESULTS/pipeline_watch_$TAG.log")
    python3 "$NE/mqtt_bench.py" --messages "${PIPE_MSGS:-200}" --results-dir "$RESULTS" --tag "$TAG" \
        --board "$BOARD" --mosquitto "$MOSQ" ${ALGOS:+--match "$ALGOS"} \
        ${LIBS:+--clients "$LIBS"} ${RB[@]+"${RB[@]}"} ${PIPE_ARGS:-} ${W[@]+"${W[@]}"} \
        || echo "[!] pipeline bench failed (or nothing matched --algo / --lib)"
fi

# -------------------------------------- 4. TLS + mTLS handshake sweep --
# ---- 2c. KEM exchange through the broker: key pair -> PUBLISH -> responder encapsulates -> decapsulate --
if stage kex mqtt liboqs && need_broker kex plain; then   # plain MQTT: no certificates
    log "KEM exchange as MQTT messages: Classic McEliece, HQC, ML-KEM-768 (public key out, ciphertext back)"
    liboqs_host; timer
    python3 "$NE/mqtt_bench.py" --kex --kex-n "${KEX_N:-50}" --results-dir "$RESULTS" --tag "$TAG" \
        --board "$BOARD" ${ALGOS:+--match "$ALGOS"} ${RB[@]+"${RB[@]}"} || echo "[!] KEM exchange failed"
fi

if stage tls mqtt openssl && need_broker tls; then
    log "TLS + mTLS handshake sweep against $BROKER (full MQTT connections; every cert x 17 groups)"
    timer
    # the broker machine's Stage 2 listeners; a combination that fails is a row with its reason
    (cd "$HERE" && HOST="$BROKER" TAG="$TAG" ITERS="${TLS_ITERS:-200}" MATCH="$ALGOS" bash network/tls_sweep.sh) \
        || echo "[!] TLS/mTLS sweep failed"
fi

# ------------------------ 5. NIST reference implementations (Stage 1) --
if stage sdith pqc reference && has "$ALGOS" SDitH; then
    log "SDitH (generic bench harness)"
    (cd "$REF" && python3 run_reference_benchmarks.py --algos SDitH --iterations $SIG_N) || echo "[!] SDitH failed"
fi
if stage faest pqc reference && has "$ALGOS" FAEST; then
    log "FAEST (flatten once, then generic bench harness)"
    [ -d "$REF/FAEST_flat" ] || bash "$REF/prepare_faest_flat.sh"
    (cd "$REF" && python3 run_reference_benchmarks.py --algos FAEST --iterations $SIG_N) || echo "[!] FAEST failed"
fi
if stage hawk pqc reference && has "$ALGOS" HAWK; then
    log "HAWK (native tests/speed: its own time-based loop, mean only)"
    # macOS: the Makefile's c99 wrapper rejects GCC-style flags, so build with clang
    HAWK_CC=cc; [ "$OS" = Darwin ] && HAWK_CC=clang
    (cd "$REF/HAWK" && python3 build.py ref \
        && cd Reference_Implementation \
        && make CC="$HAWK_CC" -s \
        && ./bin/speed > "$REF/hawk_results.txt" 2>&1 \
        && python3 "$REF/parse_native_output.py" --algo HAWK --input "$REF/hawk_results.txt" \
              ${MHZ_ARG[@]+"${MHZ_ARG[@]}"} --csv "$RESULTS/sig_summary_reference.csv") \
        || echo "[!] HAWK failed"
fi
if stage sqisign pqc reference && has "$ALGOS" SQIsign; then
    log "SQIsign (cmake ref build, NO_CYCLE_COUNTER -> ms output; PMCCNTR_EL0 SIGILLs on Pi)"
    SQ_FLAGS="-DNO_CYCLE_COUNTER -Wno-error"; SQ_GMP=()
    [ "$OS" = Darwin ] && SQ_FLAGS="$SQ_FLAGS -Wno-macro-redefined" || SQ_GMP=(-DGMP_LIBRARY=MINI)
    (cd "$REF/SQIsign" \
        && cmake -B "build_$TAG" -DSQISIGN_BUILD_TYPE=ref -DCMAKE_BUILD_TYPE=Release ${SQ_GMP[@]+"${SQ_GMP[@]}"} \
                 -DCMAKE_C_FLAGS="$SQ_FLAGS" . \
        && make -C "build_$TAG" -j"$NPROC") || echo "[!] SQIsign build failed"
    for L in 1:I 3:III 5:V; do
        lvl="${L%%:*}"; roman="${L##*:}"
        "$REF/SQIsign/build_$TAG/apps/benchmark_lvl$lvl" --iterations="$SIG_N" > "$REF/sqisign_lvl${lvl}.txt" 2>&1 \
            && python3 "$REF/parse_native_output.py" --algo SQIsign --input "$REF/sqisign_lvl${lvl}.txt" \
                  --label "SQIsign-NIST-$roman" ${MHZ_ARG[@]+"${MHZ_ARG[@]}"} --csv "$RESULTS/sig_summary_reference.csv" \
            || echo "[!] SQIsign lvl$lvl failed"
    done
fi
if stage qruov pqc reference && has "$ALGOS" QR-UOV; then
    log "QR-UOV (download NIST package if needed, then generic bench)"
    ls "$REF/QR-UOV/variants"/*/ >/dev/null 2>&1 || bash "$REF/setup_qruov.sh" || echo "[!] QR-UOV setup failed"
    (cd "$REF" && python3 run_reference_benchmarks.py --algos QR-UOV --iterations $SIG_N) \
        || echo "[!] QR-UOV failed (check algos.json variants vs package layout)"
fi

# ----------------------------------------------- 6. Pico W / Pico 2 W --
PICO_LIBS="pqclean,mldsa-native,liboqs,liboqs-r3,wolfssl,bearssl,ascon-c,reference,rweather-crypto,openssl-goldilocks"
# mqtt = the Pico W's Stage 2 + pipeline (pico/sketches/mqtt_tls_bench): needs --broker and WIFI_SSID / WIFI_PASS exported
PICO_TEST=$(has "$TESTS" pqc && printf pqc,; has "$TESTS" "mqtt,pipeline" && printf mqtt)
if stage pico "pqc,mqtt,pipeline" "$PICO_LIBS"; then
    if [ "$OS" != Darwin ]; then
        echo "[i] pico: run from the Mac (the runner flashes via /Volumes/RPI-RP2 and /dev/cu.usbmodem*)"
    elif ! pico_present; then
        echo "[i] pico: no board connected - skipped (plug it in; brand-new boards: hold BOOTSEL)"
    else
        log "Pico: signature sketches (PQClean / mldsa-native / liboqs / wolfSSL / reference / BearSSL) + MQTT over TLS / mTLS + pipeline (Pico W)"
        BROKER="$BROKER" python3 "$HERE/pico/run_benchmarks.py" ${LIBS:+--lib "$LIBS"} --test "${PICO_TEST%,}" \
            ${ALGOS:+--match "$ALGOS"} ${PICO_ARGS:-} || echo "[!] Pico run failed"
    fi
fi

# ------------- 7. Stage 1 table in the customer's form + versions (R5, R7) --
[ "$DRY" = 1 ] && { log "dry run done: nothing was built or measured. Next: ./run_all.sh --quick"; exit 0; }
log "Stage 1 table (customer's Pico form) + versions"
T=()
[ -s "$RESULTS/openssl_sig_speed_$TAG.csv" ] && T+=(--sig-speed "$RESULTS/openssl_sig_speed_$TAG.csv" \
    "$RESULTS/openssl_sig_speed_$TAG.meta" "$(${OSSL:-openssl} version | cut -d' ' -f1-2)${OPENSSL_MODULES:+ + oqsprovider}")
[ -s "$RESULTS/openssl_sig_speed_r3_$TAG.csv" ] && T+=(--sig-speed "$RESULTS/openssl_sig_speed_r3_$TAG.csv" \
    "$RESULTS/openssl_sig_speed_r3_$TAG.meta" "$(${OSSL:-openssl} version | cut -d' ' -f1-2) + oqsprovider $R3_PROV (round 3, liboqs $(git -C "$CACHE/liboqs-r3-src" describe --tags 2>/dev/null))")
[ -s "$RESULTS/wolfssl_sig_speed_$TAG.csv" ] && T+=(--sig-speed "$RESULTS/wolfssl_sig_speed_$TAG.csv" "$RESULTS/wolfssl_sig_speed_$TAG.meta" \
    "wolfSSL $(grep -o 'LIBWOLFSSL_VERSION_STRING "[^"]*"' "$CACHE/wolfssl-install/include/wolfssl/version.h" 2>/dev/null | cut -d'"' -f2)")
has "$LIBS" reference && [ -s "$RESULTS/sig_summary_reference.csv" ] && [ -s "$RESULTS/sig_meta_reference.csv" ] && \
    T+=(--summary "$RESULTS/sig_summary_reference.csv" "$RESULTS/sig_meta_reference.csv" "NIST reference impl")
[ -s "$RESULTS/liboqs_sig_speed_r3_$TAG.csv" ] && T+=(--sig-speed "$RESULTS/liboqs_sig_speed_r3_$TAG.csv" \
    "$RESULTS/liboqs_sig_speed_r3_$TAG.meta" "liboqs main $R3_LIBOQS (round 3)")
[ -s "$RESULTS/liboqs_sig_speed_$TAG.csv" ] && T+=(--sig-speed "$RESULTS/liboqs_sig_speed_$TAG.csv" "$RESULTS/liboqs_sig_speed_$TAG.meta" \
    "liboqs $(grep -o 'OQS_VERSION_TEXT "[^"]*"' "$CACHE/liboqs-host/include/oqs/oqsconfig.h" 2>/dev/null | cut -d'"' -f2)")
STAGE1_RAN=1; [ "$ONLY" = all ] || echo ",$ONLY," | grep -qiE ',(openssl|round3|liboqs|wolfssl|sdith|faest|hawk|sqisign|qruov),' || STAGE1_RAN=0
[ ${#T[@]} -gt 0 ] && [ "$STAGE1_RAN" = 1 ] && has "$TESTS" pqc && python3 "$NB/to_customer_form.py" --board "$BOARD" ${ALGOS:+--match "$ALGOS"} \
    --out "$RESULTS/stage1_customer_form_$TAG.csv" "${T[@]}"
save_versions "$TAG"
python3 "$HERE/scripts/collate_results.py" || echo "[!] collate_results.py failed"   # every run's results in one CSV

log "done - results in $RESULTS/ (Pico: pico/logs/)"
exit
}
