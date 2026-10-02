#!/usr/bin/env bash
#
# clone_algos.sh - clone NIST Onramp R2 signature reference impls from GitHub.
#
# The original NIST submission .tar.gz URLs (e.g. on hawk-sign.info / mqom.org)
# are no longer hosted; the maintained source for each algorithm is now on
# GitHub.  This script git clones the upstream dev repos.
#
# REALITY CHECK on what each repo expects:
#
#   Algo     Repo                          Build system         Layout
#   ----     ----                          ------------         ------
#   SDitH    sdith/sdith                   per-variant Make     NIST submission (works with bench_template.c)
#   HAWK     hawk-sign/dev                 make + own tests/speed.c    Generator, has its own benchmark
#   FAEST    faest-sign/faest-ref          meson + ninja        Per-variant subdirs, NOT NIST layout
#   SQIsign  SQISign/the-sqisign           cmake                Complex build with optional asm
#   QR-UOV   (qruov.org DNS fails)         manual               No active GitHub repo, no canonical mirror
#
# Only SDitH plugs straight into run_reference_benchmarks.py + bench_template.c.
# The others each need either (a) a custom adapter that drives their native
# benchmark and parses output, or (b) manual transcription of the algo's own
# benchmark output into results/sig_summary_reference.csv.  See README.md.
#
# Idempotent: existing directories are left alone; re-running retries the rest.

set -u
cd "$(dirname "$0")"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { printf "${GREEN}[ok]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[..]${NC} %s\n" "$*"; }
err()  { printf "${RED}[!!]${NC} %s\n" "$*"; }

git_clone() {
    local dest="$1" url="$2"
    if [ -d "$dest/.git" ]; then
        ok "$dest already cloned, refreshing submodules in case any are missing"
        (cd "$dest" && git submodule update --init --recursive 2>/dev/null) || true
        return 0
    fi
    if [ -d "$dest" ] && [ -n "$(ls -A "$dest" 2>/dev/null)" ]; then
        ok "$dest populated (not a git checkout), skipping"
        return 0
    fi
    warn "git clone $url -> $dest/"
    # --recurse-submodules picks up things like FAEST's catch2 dependency.
    # Skipping --depth=1 because shallow clones + submodules sometimes
    # disagree.
    if ! git clone --recurse-submodules "$url" "$dest"; then
        err "clone failed for $url"
        return 1
    fi
    ok "$dest cloned (with submodules)"
}

# ---- HAWK ---------------------------------------------------------------
# Generator repo. After `git clone` you'd run `make` to produce
# Reference_Implementation/hawk_{256,512,1024}/ with tests/speed binary.
git_clone HAWK    https://github.com/hawk-sign/dev.git    || true

# MQOM: round 3 (MQOM v3) is in liboqs main / oqs-provider 36cafae (run_all.sh round3 stage)

# ---- SDitH --------------------------------------------------------------
# Real NIST submission layout. Works with bench_template.c out of the box
# (per algos.json).
git_clone SDitH   https://github.com/sdith/sdith.git    || true

# ---- FAEST --------------------------------------------------------------
# Per-variant subdirs (faest_128f/, faest_128s/, ...) but uses meson + ninja.
git_clone FAEST   https://github.com/faest-sign/faest-ref.git    || true

# ---- SQIsign ------------------------------------------------------------
# CMake build. Won't compile with cc against bench_template.c.
git_clone SQIsign https://github.com/SQISign/the-sqisign.git    || true

# ---- QR-UOV -------------------------------------------------------------
# No accessible repo. Note where the user can dig manually.
mkdir -p QR-UOV
if [ ! -f QR-UOV/README.txt ]; then
    cat > QR-UOV/README.txt <<'EOT'
QR-UOV: no canonical GitHub repo and qruov.org DNS no longer resolves.

Two paths forward:

1. NIST hosts archived submission packages at
   https://csrc.nist.gov/projects/pqc-dig-sig/round-2-additional-signatures
   Look for the QR-UOV round-2 submission .zip and extract here.

2. The pqov/pqov-paper repo has UOV variants and includes notes on QR-UOV
   internal structure but is not a drop-in.

If you place the unpacked submission package in this directory matching the
standard NIST layout (Reference_Implementation/<variant>/api.h ...), then
run_reference_benchmarks.py --algos QR-UOV will pick it up.
EOT
    ok "QR-UOV: README.txt with manual-download instructions written"
fi

cat <<EOF

----------------------------------------------------------------------
Clones complete.  Next steps depend on the algorithm:

  SDitH:    works with the generic harness.  Run:
              python run_reference_benchmarks.py --algos SDitH --probe-only

  HAWK:     uses its own benchmark.  Build with:
              cd HAWK  &&  make
            Then run tests/speed and pipe to a CSV by hand
            (see README.md for the helper).

  MQOM:     uses MQOM2_VARIANT env var.  Build a single variant with:
              cd MQOM
              MQOM2_VARIANT=cat1_gf256_fast_r3 make
              ./benchmark/test_bench
            Repeat per variant; see README.md.

  FAEST:    uses meson+ninja.  Build with:
              cd FAEST  &&  mkdir build && cd build && meson .. && ninja
            Then run the variant-specific bench binaries.

  SQIsign:  uses cmake.  Build with:
              cd SQIsign
              mkdir build && cd build
              cmake -DSQISIGN_BUILD_TYPE=ref ..
              make
            Then run test/SQIsign_test_bench lvl1 (or lvl3/lvl5).

  QR-UOV:   see QR-UOV/README.txt for manual install steps.
----------------------------------------------------------------------
EOF
