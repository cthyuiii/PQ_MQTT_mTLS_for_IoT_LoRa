#!/usr/bin/env bash
# setup_round3.sh <SDitH | QR-UOV | FAEST | SQIsign>... - the NIST round 3 code of these four for the reference stage
# (the same code the Pico runs), fetched and built once per machine into $IOT_PQC_CACHE/ref-r3 (default
# ~/.cache/iot-pqc), out of the repo. algos.json then points the generic bench (bench_template.c) at each parameter
# set's NIST API; run_reference_benchmarks.py resolves {CACHE} in its paths.
#   SDitH   NIST round 3 package (sdith3_submission_package.zip, 31 Aug 2026): per set, its CMake builds libsdith /
#           libsha3 / libaes (portable C); the bench links generator/sign.c (the NIST API) against them. 12 sets.
#   QR-UOV  NIST round 3 package (QR_UOV - Round3.zip): one reference tree, -DQRUOV_PARAM_<set> (OpenSSL AES PRG, as
#           its GNUmakefile's default). 15 sets.
#   FAEST   faest-ref v3.0.0, built by its own meson build (meson + ninja needed): libfaest_no_random / libfaest, and
#           each set's crypto_sign.c. 12 sets.
#   SQIsign the-sqisign f417ebd (round 3), CMake ref build (64-bit field arithmetic on a 64-bit host): the bench links
#           each level's NIST API library. 3 levels.
set -euo pipefail
C="${IOT_PQC_CACHE:-$HOME/.cache/iot-pqc}"; R="$C/ref-r3"
NIST=https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents
NPROC=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc)
mkdir -p "$R"
fetch() {  # fetch <url> <zip>: a cached copy (also the Pico port's, r3-packages/) or a download
    [ -s "$2" ] && return 0
    curl -fsSL -o "$2.part" "$1" && mv "$2.part" "$2"
}
for A in "$@"; do case "$A" in
SDitH)
    D="$R/SDitH"
    if [ ! -d "$D/Reference_Implementation" ]; then
        Z="$C/r3-packages/sdith3.zip"; mkdir -p "$C/r3-packages"
        fetch "$NIST/sdith3_submission_package.zip" "$Z"
        rm -rf "$D.tmp" && mkdir -p "$D.tmp" && unzip -q "$Z" 'submission_package/*' -x '__MACOSX/*' -d "$D.tmp"
        chmod -R u+w "$D.tmp"
        rm -rf "$D" && mv "$D.tmp/submission_package" "$D" && rm -rf "$D.tmp"
    fi
    for v in cat1_fast cat1_short cat1_fast_cipherpow cat1_short_cipherpow cat3_fast cat3_short cat3_fast_cipherpow \
             cat3_short_cipherpow cat5_fast cat5_short cat5_fast_cipherpow cat5_short_cipherpow; do
        S="$D/Reference_Implementation/$v"
        [ -f "$S/build/libsdith.a" ] && continue
        # their Release flags add -Werror (a newer compiler's new warning would fail the build) and -g3: without both
        cmake -Wno-dev -S "$S" -B "$S/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_KATS=OFF \
              -DCMAKE_C_FLAGS_RELEASE="-O3 -DNDEBUG" >/dev/null
        cmake --build "$S/build" -j"$NPROC" --target sdith >/dev/null
    done
    echo "[+] SDitH round 3 (12 sets) -> $D" ;;
QR-UOV)
    D="$R/QR-UOV"
    if [ ! -f "$D/ref/qruov.c" ]; then
        Z="$C/r3-packages/qruov_r3.zip"; mkdir -p "$C/r3-packages"
        fetch "$NIST/QR_UOV%20-%20Round3.zip" "$Z"
        rm -rf "$D.tmp" && mkdir -p "$D.tmp" && unzip -q "$Z" -d "$D.tmp" && chmod -R u+w "$D.tmp"  # the zip's folders are read-only
        mkdir -p "$D" && rm -rf "$D/ref" && mv "$(dirname "$(find "$D.tmp" -path '*Reference_Implementation/ref/qruov.c' | head -1)")" "$D/ref"
        rm -rf "$D.tmp"
    fi
    echo "[+] QR-UOV round 3 (15 sets) -> $D/ref" ;;
FAEST)
    D="$C/faest-v3.0.0"   # shared with pico/sketches/faest_bench/update_src.sh
    [ -d "$D" ] || git clone -q --branch v3.0.0 https://github.com/faest-sign/faest-ref.git "$D"
    if [ ! -f "$D/build_release/libfaest_no_random.a" ]; then
        command -v meson >/dev/null || { echo "[-] FAEST needs meson + ninja (apt install meson ninja-build / brew install meson)"; exit 1; }
        (cd "$D" && meson setup build_release -Dbuildtype=release >/dev/null && ninja -C build_release >/dev/null)
    fi
    ln -sfn "$D" "$R/FAEST"
    echo "[+] FAEST 3.0 (12 sets) -> $D/build_release" ;;
SQIsign)
    D="$R/SQIsign"
    [ -d "$D" ] || git clone -q https://github.com/SQISign/the-sqisign.git "$D"
    git -C "$D" checkout -q f417ebd
    if [ ! -f "$D/build/src/libsqisign_p664_17_nistapi.a" ]; then
        cmake -Wno-dev -S "$D" -B "$D/build" -DCMAKE_BUILD_TYPE=Release -DSQISIGN_BUILD_TYPE=ref -DENABLE_TESTS=OFF \
              -DENABLE_STRICT=OFF >/dev/null
        cmake --build "$D/build" -j"$NPROC" --target sqisign_p324_3_nistapi sqisign_p500_27_nistapi \
              sqisign_p664_17_nistapi >/dev/null
    fi
    for v in p324_3 p500_27 p664_17; do  # per level: the API header, namespaced as its library, and its archives
        B="$D/bench/$v"; mkdir -p "$B"
        printf '#define SQISIGN_BUILD_TYPE_REF\n#define ENABLE_SIGN\n#define SQISIGN_VARIANT %s\n#include "%s"\n' \
            "$v" "$D/src/nistapi/$v/api.h" > "$B/api.h"
        echo "/* the level's code is linked from its archives (setup_round3.sh); bench_template.c has main() */" > "$B/stub.c"
        L=$(find "$D/build/src" -name '*.a' | grep -v test | grep -e "$v" -e common | tr '\n' ' ')
        echo "$L $L" > "$B/libs.txt"   # twice: one pass of each archive leaves cross references (GNU ld) unresolved
    done
    echo "[+] SQIsign round 3 (3 levels) -> $D/build" ;;
*) echo "usage: $0 SDitH | QR-UOV | FAEST | SQIsign ..."; exit 1 ;;
esac; done
