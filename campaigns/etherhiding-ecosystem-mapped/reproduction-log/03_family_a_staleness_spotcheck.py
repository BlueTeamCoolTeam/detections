#!/usr/bin/env python3
"""
The authorization-cdn-etherhiding-clickfix post's operator 1/2/3 confirmed-site
counts are carried into the combined post unchanged (not fully re-run) - this
script spot-checks a small, deterministically-selected sample from each list,
live, ~3 days after original capture (2026-07-08 -> now), to see whether the
carried-over numbers are still a reasonable floor rather than badly stale.

Deterministic sample selection (not true random, for reproducibility): every
Nth line of each file, N chosen so each operator contributes up to 5 sites
(op3 only has 3 total, so all 3 are checked).

Detection logic reused as-is from the published post's own checker
(03_live_verification_checker.py in the authorization-cdn revalidation folder):
brute-force every atob() blob against all 256 single-byte XOR keys, check the
decoded text for the kit's run-once guard variable plus >=2 of
polygon/eth_call/api.php.
"""
import base64
import re
import urllib.request
from pathlib import Path

HERE = Path(__file__).parent

ATOB = re.compile(r"atob\(['\"]([A-Za-z0-9+/=]{120,})['\"]\)")
GUARD = re.compile(r"window\['_[0-9a-f]{8,}'\]")

FILES = {
    "op1_xdav": "family_a_operator1_xdav_confirmed.txt",
    "op2": "family_a_operator2_confirmed.txt",
    "op3": "family_a_operator3_confirmed.txt",
}


def sample(name, n=5):
    lines = [l.strip() for l in (HERE / FILES[name]).read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    if len(lines) <= n:
        return lines
    step = max(1, len(lines) // n)
    return lines[::step][:n]


def is_kit(decoded):
    d = decoded.lower()
    hits = sum(x in d for x in ("polygon", "eth_call", "api.php"))
    return (GUARD.search(decoded) is not None and hits >= 2) or ("api.php?s=" in d and "polygon" in d)


def check(host):
    for scheme in ("https://", "http://"):
        try:
            req = urllib.request.Request(scheme + host + "/", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read().decode("utf-8", "replace")
        except Exception as e:
            continue
        for blob in ATOB.findall(body):
            try:
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
            except Exception:
                continue
            for key in range(256):
                decoded = bytes(b ^ key for b in raw).decode("utf-8", "replace")
                if is_kit(decoded):
                    return "CONFIRMED", key
        return "REACHABLE_NO_MATCH", None
    return "UNREACHABLE", None


def main():
    for name in FILES:
        hosts = sample(name)
        print(f"\n=== {name}: sampling {len(hosts)} of {sum(1 for _ in (HERE/FILES[name]).open())} ===")
        for h in hosts:
            status, key = check(h)
            print(f"  {h}: {status}" + (f" (key={key})" if key is not None else ""))


if __name__ == "__main__":
    main()
