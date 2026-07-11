#!/usr/bin/env python3
"""
Directly answers: do we have an actual saved, decoded copy of the injected
script that shows the "BW panel" framework markers (__BW_MODE_RUN__,
site_repair_state) in context - not just a claim repeating what an earlier
report said, and not just a hardcoded search string embedded in a checker
script?

Prior state: the only prior evidence was investigate_cedahr_mismatch.py
(in the mamkor investigation's artifacts), which required a /tmp/cedahr.html
file that only ever existed on the original Kali analysis host and is not
present in this repo or session. No decoded output was ever saved
alongside it. This script re-fetches cedahr.com fresh (still in our
current, 2026-07-11-revalidated confirmed list) and re-derives the decode
independently, saving the actual result this time.
"""
import re

HTML_PATH = "cedahr_fresh_fetch.html"  # fetched fresh via curl this session

with open(HTML_PATH, encoding="utf-8", errors="replace") as f:
    html = f.read()

m_key = re.search(r"var\s+_0xd247ab\s*=\s*(\d+)", html)
m_blob = re.search(r"_0x08e24a\s*=\s*'([A-Za-z0-9+/=]+)'", html)

if not (m_key and m_blob):
    print("FAIL: key or blob pattern not found in fresh fetch - page may have changed shape.")
    raise SystemExit(1)

key = int(m_key.group(1))
blob = m_blob.group(1)
print(f"Key variable _0xd247ab = {key}")
print(f"Blob variable _0x08e24a length = {len(blob)}")

import base64
raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
dec = bytes(b ^ key for b in raw)
text = dec.decode("utf-8", errors="replace")

with open("cedahr_decoded_injected_script.js", "w", encoding="utf-8") as f:
    f.write(text)
print(f"\nDecoded script written to cedahr_decoded_injected_script.js ({len(text)} bytes)")

print("\n=== Framework marker check (direct substring search on the ACTUAL decoded text) ===")
for marker in ["__BW_MODE_RUN__", "site_repair_state", "v1.js", "v9.js"]:
    present = marker in text
    print(f"  {marker!r}: {'FOUND' if present else 'NOT FOUND'}")

m_contract = re.search(r"CONTRACT_ADDRESS:'([^']+)'", text)
m_selector = re.search(r"FUNCTION_SELECTOR:'([^']+)'", text)
print(f"\nCONTRACT_ADDRESS: {m_contract.group(1) if m_contract else 'NOT FOUND'}")
print(f"FUNCTION_SELECTOR: {m_selector.group(1) if m_selector else 'NOT FOUND'}")

print("\n=== First 400 characters of decoded script (for direct visual inspection) ===")
print(text[:400])
