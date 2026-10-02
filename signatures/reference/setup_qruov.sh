#!/usr/bin/env bash
# setup_qruov.sh - fetch + prepare + register the QR-UOV round-2 submission.
#
# QR-UOV's package does NOT follow the standard NIST layout: there is no
# per-variant api.h. Instead, Reference_Implementation/ref/ is a single
# source tree and api.h + qruov_config.h are GENERATED per parameter set by
# small generator programs (api_h_gen.c / qruov_config_h_gen.c) driven by -D
# flags listed in qruov_config.src. This script:
#
#   1. downloads + extracts the NIST round-2 zip (109 MB) if not present
#   2. for each variant: creates QR-UOV/variants/<v>/ with the ref sources,
#      generates qruov_config.h and api.h (no OpenSSL needed for this step)
#   3. registers the variants in algos.json as generic-bench entries
#
# Then:    python3 run_reference_benchmarks.py --algos QR-UOV --probe-only
#
# Build requirements for the probe/bench step (not for this script):
#   - OpenSSL dev headers: QR-UOV's mgf.c/rng.c use EVP SHAKE + AES
#     (Pi: sudo apt install libssl-dev; macOS: brew openssl@3 - export
#      CPATH/LIBRARY_PATH like run_all.sh does)
#   - OpenSSL >= 3.3 uses the EVP_DigestSqueeze path; older (Pi 3.0.x)
#     falls back to the legacy XOF code in mgf.c automatically.
#   - OpenMP pragmas: compiled with -fopenmp on Linux (gcc); omitted on
#     macOS clang (pragmas are ignored -> single-threaded, still correct).
#
# Usage:
#   ./setup_qruov.sh           # primary q127/L3 set: category I, III, V
#   ./setup_qruov.sh --all     # all 12 round-2 parameter sets
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HERE/QR-UOV"
URL="https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-2/submission-pkg/qr-uov-submission-round2.zip"
ZIP="$DEST/qr-uov-submission-round2.zip"

PRIMARY="qruov1q127L3v156m54 qruov3q127L3v228m78 qruov5q127L3v306m105"
ALL="qruov1q7L10v740m100 qruov1q31L3v165m60 qruov1q31L10v600m70 qruov1q127L3v156m54 \
qruov3q7L10v1100m140 qruov3q31L3v246m87 qruov3q31L10v890m100 qruov3q127L3v228m78 \
qruov5q7L10v1490m190 qruov5q31L3v324m114 qruov5q31L10v1120m120 qruov5q127L3v306m105"
VARIANTS="$PRIMARY"
[ "${1:-}" = "--all" ] && VARIANTS="$ALL"

# ----- 1. download + extract -----
mkdir -p "$DEST"
if ! find "$DEST" -maxdepth 3 -name "qruov_config.src" | grep -q .; then
    if [ ! -f "$ZIP" ]; then
        echo "[+] downloading QR-UOV round-2 package (109 MB)..."
        wget -O "$ZIP" "$URL" || curl -L -o "$ZIP" "$URL"
    fi
    echo "[+] extracting..."
    unzip -q -o "$ZIP" -d "$DEST"
fi

# locate the Reference_Implementation dir (package root has spaces in name)
RI="$(dirname "$(find "$DEST" -maxdepth 3 -path "*Reference_Implementation*" -name qruov_config.src | head -1)")"
[ -n "$RI" ] && [ -d "$RI/ref" ] || { echo "[-] Reference_Implementation/ref not found under $DEST"; exit 1; }
echo "[+] reference impl: $RI"

# ----- 2. per-variant source dirs + generated headers -----
for V in $VARIANTS; do
    T="$DEST/variants/$V"
    rm -rf "$T" 2>/dev/null || true     # idempotent; overwrite below if rm blocked
    mkdir -p "$T"
    cp -f "$RI/ref/"* "$T/"
    # strip iCloud sync conflict copies (e.g. "mgf 2.c") so the runner's *.c glob
    # doesn't pick up stale/duplicate sources
    find "$T" -maxdepth 1 \( -name "* [0-9].c" -o -name "* [0-9].h" \) -delete 2>/dev/null || true
    # x86intrin.h is x86-only; guard it so the ref build compiles on ARM (Pi / Apple Silicon)
    python3 - "$T/matrix.c" <<'PYG'
import sys
p=sys.argv[1]
try: s=open(p).read()
except FileNotFoundError: sys.exit(0)
b="#include <x86intrin.h>"
if "defined(__x86_64__) || defined(__i386__)" not in s and b in s:
    open(p,"w").write(s.replace(b,"#if defined(__x86_64__) || defined(__i386__)\n"+b+"\n#endif",1))
PYG
    # mgf.c calls OpenSSL's internal SHA3_squeeze (unexported in 3.x); rewrite to
    # the public EVP_DigestSqueeze (OpenSSL >= 3.3) so it links on modern OpenSSL
    python3 - "$T/mgf.c" <<'PYM'
import sys
p=sys.argv[1]
try: s=open(p).read()
except FileNotFoundError: sys.exit(0)
if "EVP_DigestSqueeze(ctx->mdctx, dest, n1)" in s: sys.exit(0)
R1_OLD='#else\n\n// from openssl-1.1.1t/crypto/sha/keccak1600.c'
R1_NEW=('#else\n\n#if OPENSSL_VERSION_NUMBER >= 0x30300000L\n'
 'uint8_t * MGF_yield (MGF_CTX ctx, uint8_t * dest, const size_t n1) {\n'
 '  EVP_DigestSqueeze(ctx->mdctx, dest, n1) ;\n  return dest ;\n}\n'
 'void MGF_final (MGF_CTX ctx) {\n  EVP_MD_CTX_free(ctx->mdctx) ;\n  return ;\n}\n'
 '#else\n\n// from openssl-1.1.1t/crypto/sha/keccak1600.c')
R2_OLD=('void MGF_final (MGF_CTX ctx) {\n  EVP_DigestFinalXOF_END(ctx->mdctx) ;\n'
 '  EVP_MD_CTX_free(ctx->mdctx);\n  OPENSSL_cleanse(ctx->pool, QRUOV_SHAKE_BSZ+1);\n  return ;\n}\n\n#endif')
R2_NEW=R2_OLD.replace('\n\n#endif','\n\n#endif /* OPENSSL>=3.3 */\n\n#endif')
if R1_OLD in s and R2_OLD in s:
    open(p,"w").write(s.replace(R1_OLD,R1_NEW,1).replace(R2_OLD,R2_NEW,1))
PYM
    # drop the upstream Makefile so the runner doesn't auto-extract its -D flags
    # (it mentions -DQRUOV_PRG_SHAKE in a comment, which would flip the PRG)
    rm -f "$T/Makefile" 2>/dev/null || : > "$T/Makefile"
    grep "$V" "$RI/qruov_config.src" | head -1 > "$T/qruov_config.txt"
    [ -s "$T/qruov_config.txt" ] || { echo "[-] $V not in qruov_config.src"; continue; }
    GEN="$(mktemp -d)"        # build generator binaries outside the repo
    (cd "$T" \
      && cc @qruov_config.txt -DQRUOV_PLATFORM=ref -DQRUOV_CONFIG_H_GEN -O2 qruov_config_h_gen.c -o "$GEN/cfg" \
      && "$GEN/cfg" > qruov_config.h \
      && cc -DAPI_H_GEN -O2 api_h_gen.c -o "$GEN/api" \
      && "$GEN/api" > api.h) \
      || { echo "[-] header generation failed for $V"; rm -rf "$GEN"; continue; }
    rm -rf "$GEN"
    echo "[+] $V  ($(grep CRYPTO_PUBLICKEYBYTES "$T/api.h" | head -1 | awk '{print "pk="$3}') )"
done

# ----- 3. register in algos.json -----
python3 - "$HERE" "$VARIANTS" <<'PYEOF'
import json, sys
from pathlib import Path

here = Path(sys.argv[1]); variants = sys.argv[2].split()
cflags = ["-O3", "-fwrapv", "-DQRUOV_PLATFORM=ref",
          "-Wno-deprecated-declarations", "-Wno-unused-result", "-Wno-error"]
import platform
if platform.system() == "Linux":
    cflags.append("-fopenmp")          # gcc; macOS clang has no default OpenMP

ROMAN = {"1": "I", "3": "III", "5": "V"}
entries = []
for v in variants:
    d = here / "QR-UOV" / "variants" / v
    if not (d / "api.h").exists():
        continue
    entries.append({
        "name": f"QR-UOV-{ROMAN.get(v[5], v[5])}-{v[6:].split('v')[0]}",   # e.g. QR-UOV-I-q127L3
        "dir": f"variants/{v}",
        # PQCgenKAT has main(); the *_gen.c are header generators; rng.c
        # defines randombytes which bench_template.c already provides.
        "exclude_files": ["PQCgenKAT_sign.c", "api_h_gen.c", "qruov_config_h_gen.c", "rng.c"],
        "extra_cflags": cflags,
        "extra_ldflags": ["-lcrypto", "-lm"],
    })

algos_json = here / "algos.json"
algos = json.loads(algos_json.read_text())
algos["QR-UOV"]["build_strategy"] = "generic-bench"
algos["QR-UOV"]["variants"] = entries
algos_json.write_text(json.dumps(algos, indent=4) + "\n")
print(f"[+] registered {len(entries)} QR-UOV variants in algos.json:")
for e in entries:
    print(f"      {e['name']:24s} {e['dir']}")
PYEOF

echo
echo "[+] done. Next:"
echo "      python3 run_reference_benchmarks.py --algos QR-UOV --probe-only"
echo "      python3 run_reference_benchmarks.py --algos QR-UOV"
echo "    (macOS: export CPATH=\$(brew --prefix openssl@3)/include LIBRARY_PATH=\$(brew --prefix openssl@3)/lib first)"
