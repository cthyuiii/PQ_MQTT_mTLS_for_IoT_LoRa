#!/usr/bin/env bash
#
# clone_algos.sh - clone the signature reference code that is not round 3: HAWK (hawk-sign/dev; HAWK has been
# withdrawn from round 3). SDitH, FAEST, SQIsign and QR-UOV run their round 3 code: setup_round3.sh fetches and
# builds it. MQOM, MAYO, SNOVA and UOV are measured through liboqs / oqs-provider (run_all.sh round3 stage).
#
# Idempotent: an existing directory is left alone.

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

cat <<EOF

----------------------------------------------------------------------
HAWK: uses its own benchmark (README.md has the recipe; run_all.sh's hawk stage runs it).
SDitH / FAEST / SQIsign / QR-UOV (round 3):  ./setup_round3.sh SDitH QR-UOV FAEST SQIsign
----------------------------------------------------------------------
EOF
