"""Provenance for the benchmark drivers (project plan R7: every result records its software, firmware and
library versions): board_name() for the Board column, versions() for versions_<tag>.json and run metadata."""

from __future__ import annotations

import os
import platform
import re
import subprocess
from pathlib import Path


def board_name() -> str:
    """``pi5`` / ``pi4`` / ... on a Raspberry Pi (matches the Pico CSV's Board column), else OS-arch."""
    model = Path("/proc/device-tree/model")
    text = model.read_text().strip("\x00\n") if model.exists() else ""
    m = re.search(r"Raspberry Pi (\d+|Zero 2)", text)
    return f"pi{m.group(1).replace(' ', '').lower()}" if m else f"{platform.system()}-{platform.machine()}"


def _sh(cmd: str):
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15).stdout.strip()
        return out or None
    except Exception:
        return None


def versions() -> dict:
    """Best-effort snapshot of everything that can change a number. Missing tools -> None."""
    here = Path(__file__).resolve().parent
    ossl = os.environ.get("OSSL", "openssl")
    model = Path("/proc/device-tree/model")
    v = {
        "board": board_name(),
        "model": model.read_text().strip("\x00\n") if model.exists() else platform.processor(),
        "os": _sh(". /etc/os-release && echo $PRETTY_NAME") or platform.platform(),
        "kernel": platform.release(),
        "firmware": _sh("vcgencmd version | tr '\\n' ' '"),
        "cpu_aes": ("aes" in Path("/proc/cpuinfo").read_text().split()) if Path("/proc/cpuinfo").exists() else None,
        "cc": _sh("cc --version | head -1"),
        "python": platform.python_version(),
        "openssl_cli": _sh(f"{ossl} version"),
        # oqs-provider's build info names the liboqs compiled into it (Falcon/MAYO/SNOVA inside OpenSSL)
        "oqsprovider": _sh(f"{ossl} list -providers -verbose -provider oqsprovider 2>/dev/null | grep -i 'build info'"),
        "liboqs_system": _sh("pkg-config --modversion liboqs"),  # installed liboqs (Homebrew / apt), if any
        "liboqs_bench": None,  # the liboqs 0.16 build the liboqs stage and the Pico use (below)
        "mosquitto": _sh("{ mosquitto -h || /usr/sbin/mosquitto -h; } 2>&1 | grep -o 'mosquitto version [0-9.]*' | head -1"),
        "wolfssl": None,
        "ascon_c": None,
    }
    cache = Path(os.environ.get("IOT_PQC_CACHE", Path.home() / ".cache/iot-pqc"))
    cfg = cache / "liboqs-host/include/oqs/oqsconfig.h"
    if cfg.exists():
        m = re.search(r'OQS_VERSION_TEXT "([^"]+)"', cfg.read_text())
        v["liboqs_bench"] = m.group(1) if m else None
    if (cache / "liboqs-r3-src").exists():  # liboqs main under the round 3 oqs-provider (its build info says 0.16.0)
        v["liboqs_round3"] = _sh(f"git -C '{cache}/liboqs-r3-src' describe --tags")
    hdr = Path(os.environ.get("WOLFSSL_PREFIX", cache / "wolfssl-install")) / "include/wolfssl/version.h"
    if hdr.exists():
        m = re.search(r'LIBWOLFSSL_VERSION_STRING "([^"]+)"', hdr.read_text())
        v["wolfssl"] = m and m.group(1)
    m = re.search(r"^REV=(\w+)", (here / "build_ascon.sh").read_text(), re.M)
    v["ascon_c"] = m and m.group(1)
    return v

