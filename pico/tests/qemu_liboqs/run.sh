#!/usr/bin/env bash
# run.sh - check and measure liboqs_bench's Keccak swap (keccak_swap.sh) without a Pico, by running the
# Pico build of liboqs in QEMU:
#   Cortex-M0+ code on mps2-an385 (a Cortex-M3 board; ARMv6-M code runs on it unchanged)
#   Cortex-M33 code on mps2-an505
# For each CPU, the stock library (plain64) and each XKCP variant run test.c: SHA-3 known answers,
# then keygen / sign / verify per algorithm with the same deterministic RNG. A variant passes only if
# its known answers pass and every algorithm's pk | sk | sig digest equals the stock build's.
# Reports *instructions* per operation: QEMU is not cycle-accurate (M0+ loads and taken branches cost 2
# cycles, and the Pico's flash cache isn't modelled), so the board run gives the real time.
#   bash pico/tests/qemu_liboqs/run.sh        needs qemu-system-arm (brew install qemu / apt install qemu-system-arm)
# Writes pico/logs/qemu_liboqs_keccak.csv.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PICO="$(cd "$HERE/../.." && pwd)"
CACHE=${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}
command -v qemu-system-arm >/dev/null || { echo "[-] needs qemu-system-arm (brew install qemu)"; exit 1; }
bash "$PICO/sketches/liboqs_bench/make_liboqs_lib.sh"          # the stock Pico library (skips when up to date)
L="$CACHE/arduino-libs/liboqs/src"
GCC=""
for d in "$HOME"/Library/Arduino15/packages/rp2040/tools/pqt-gcc/*/bin "$HOME"/.arduino15/packages/rp2040/tools/pqt-gcc/*/bin; do
    [ -x "$d/arm-none-eabi-gcc" ] && GCC="$d"
done
OUT=$(mktemp -d); trap 'rm -rf "$OUT"' EXIT

one() {  # one <mcu> <impl>: build, run in QEMU, output in $OUT/<mcu>-<impl>.txt
    local mcu=$1 impl=$2 lib=$L/$1/liboqs.a cpu machine text ram
    case $mcu in
        cortex-m0plus) cpu="-mcpu=cortex-m0plus -mthumb -march=armv6-m"; machine=mps2-an385; text=0x00000000; ram=0x20000000 ;;
        cortex-m33)    cpu="-mcpu=cortex-m33 -mthumb -march=armv8-m.main+fp+dsp -mfloat-abi=softfp"
                       machine=mps2-an505; text=0x10000000; ram=0x38000000 ;;
    esac
    if [ "$impl" != plain64 ]; then
        bash "$PICO/sketches/liboqs_bench/keccak_swap.sh" "$lib" "$mcu" "$impl" "$OUT/$mcu-$impl.a"; lib="$OUT/$mcu-$impl.a"
    fi
    "$GCC/arm-none-eabi-gcc" $cpu -O2 -I"$L" -nostartfiles --specs=rdimon.specs -T "$HERE/link.ld" \
        -Wl,--defsym=TEXT=$text,--defsym=RAM=$ram -Wl,--gc-sections "$HERE/startup.c" "$HERE/test.c" "$lib" \
        -o "$OUT/$mcu-$impl.elf"
    timeout 3600 qemu-system-arm -M $machine -nographic -icount shift=0 -semihosting-config enable=on,target=native \
        -kernel "$OUT/$mcu-$impl.elf" > "$OUT/$mcu-$impl.txt" 2>&1 || echo "exit,$?" >> "$OUT/$mcu-$impl.txt"
}
RUNS="cortex-m0plus:plain64 cortex-m0plus:armv6m-u1 cortex-m0plus:armv6m-u2 cortex-m0plus:c32 cortex-m33:plain64 cortex-m33:armv7m cortex-m33:c32"
for r in $RUNS; do one "${r%%:*}" "${r#*:}" & done
wait
python3 - "$OUT" "$PICO/logs/qemu_liboqs_keccak.csv" $RUNS <<'EOF'
import csv, sys
out, csv_path, runs = sys.argv[1], sys.argv[2], [r.split(":") for r in sys.argv[3:]]
res, bad = {}, 0
for mcu, impl in runs:
    lines = open(f"{out}/{mcu}-{impl}.txt", errors="replace").read().splitlines()
    kat = next((l.split(",")[1] for l in lines if l.startswith("kat,")), "NO_OUTPUT")
    algs = {f[1]: f[2:] for f in (l.split(",") for l in lines if l.startswith("alg,"))}
    keccak = next((int(l.split(",")[2]) for l in lines if l.startswith("keccak,")), None)
    res[mcu, impl] = kat, keccak, algs
    if kat != "OK" or any(l.startswith("exit,") for l in lines):
        print(f"[-] {mcu} {impl}: known answers {kat}", *[l for l in lines if l.startswith("exit,")]); bad = 1
rows = []
for mcu, impl in runs:
    kat, keccak, algs = res[mcu, impl]
    base = res[mcu, "plain64"]
    same = all(algs.get(a, [None] * 5)[4] == b[4] and algs[a][3] == "ok" for a, b in base[2].items())
    if not same:
        print(f"[-] {mcu} {impl}: signatures differ from the stock build"); bad = 1
    print(f"\n{mcu} {impl}: known answers {kat}, signatures {'identical to stock' if same else 'DIFFERENT'}; "
          f"SHAKE256 1000 B -> 1000 B: {keccak:,} instructions ({base[1] / keccak:.2f}x)")
    for a, v in algs.items():
        b = base[2][a]
        ratios = "  ".join(f"{op} {int(x):>13,} ({int(y) / int(x):.2f}x)" for op, x, y in zip(("keygen", "sign", "verify"), v[:3], b[:3]))
        print(f"  {a:26s} {ratios}")
        rows.append(dict(cpu=mcu, keccak=impl, algorithm=a, keygen_insns=v[0], sign_insns=v[1], verify_insns=v[2],
                         speedup_keygen=f"{int(b[0]) / int(v[0]):.3f}", speedup_sign=f"{int(b[1]) / int(v[1]):.3f}",
                         speedup_verify=f"{int(b[2]) / int(v[2]):.3f}", same_output=same, known_answers=kat))
with open(csv_path, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
print(f"\n[+] wrote {csv_path}" + ("" if not bad else "\n[-] FAILED"))
sys.exit(bad)
EOF
