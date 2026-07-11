#!/usr/bin/env python3
"""
confirm.py -- BW panel EtherHiding investigation, batch 3 of 3.

For each candidate hostname from candidate_hosts.json, fetch https://<host>/
with a realistic browser UA, full response up to 20MB, and check for the
malicious injected <script>. The injection is polymorphic:

  1. Cleartext            -- substring present directly
  2. atob(blob) + ((byte-SUB+256)&255)^XOR arithmetic (SUB/XOR unknown, brute 0-255 x 0-255)
  3. Single-byte XOR of a base64 blob (brute 0-255)
  4. 256-byte S-box substitution table (literal array in the script; apply as translate table)
  5. Bare var assignment  var k=<int>, d="<base64>"; decoded as base64(d) XOR k (key in cleartext)

CONFIRMED only if decoded content contains "926d6454" (this operator's
contract prefix, case-insensitive). If a DIFFERENT known sibling contract
prefix decodes out (b6bc9e1d, 83833c5d, 08207b08), record as sibling-operator.

Uses bytes.translate() with precomputed 256-byte tables for all brute-force
sweeps -- no per-byte Python loops in the hot path.
"""
import json
import re
import sys
import time
import base64
import binascii
import gzip
import zlib
import urllib.request
import urllib.error
import urllib.parse

try:
    import brotli
except ImportError:
    brotli = None
try:
    import zstandard
except ImportError:
    zstandard = None


def decompress_body(resp, raw_body):
    """
    urllib does NOT auto-decompress response bodies. Many of these WordPress
    hosts serve gzip/br/zstd-encoded HTML (CDN/caching plugins), so failing
    to decompress silently turns every page into binary garbage that never
    matches any marker -- a false "clean" verdict. Decompress based on the
    Content-Encoding header (falling back to sniffing magic bytes).
    """
    encoding = ""
    try:
        encoding = (resp.headers.get("Content-Encoding") or "").lower()
    except Exception:
        pass

    body = raw_body
    try:
        if "gzip" in encoding or raw_body[:2] == b"\x1f\x8b":
            body = gzip.decompress(raw_body)
        elif "br" in encoding and brotli is not None:
            body = brotli.decompress(raw_body)
        elif "zstd" in encoding and zstandard is not None:
            body = zstandard.ZstdDecompressor().decompress(raw_body, max_output_size=100 * 1024 * 1024)
        elif "deflate" in encoding:
            try:
                body = zlib.decompress(raw_body)
            except zlib.error:
                body = zlib.decompress(raw_body, -zlib.MAX_WBITS)
    except Exception:
        # decompression failed -- fall back to raw bytes rather than crash
        body = raw_body
    return body

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
TIMEOUT = 25
MAX_BYTES = 20 * 1024 * 1024  # 20MB cap

KEY_PATH = "/tmp/claude-1000/-home-bob-Claude-Projects-Malware-Analysis/c0ca938f-b5b4-4457-b750-83102711c171/scratchpad/urlscan_key"
try:
    with open(KEY_PATH) as _f:
        URLSCAN_API_KEY = _f.read().strip()
except Exception:
    URLSCAN_API_KEY = None

TARGET = "926d6454"
SIBLINGS = {
    "b6bc9e1d": "sibling-B6BC9E1D",
    "83833c5d": "sibling-83833C5D",
    "08207b08": "sibling-08207B08",
}
ALL_MARKERS = [TARGET] + list(SIBLINGS.keys())

FRAMEWORK_MARKERS = ["__BW_MODE_RUN__", "site_repair_state", "CONTRACT_ADDRESS", "FUNCTION_SELECTOR"]
SELECTOR = "b68d1809"

# This operator's own assigned C2 domains (batch 3). Some injections turn out
# to be a plain <script data-src="https://<c2>/api/css.js?..."> lazy-load tag
# rather than an obfuscated inline blob -- the domain string sits in cleartext
# in the page HTML even though the actual EtherHiding/contract logic lives in
# the (often now-dead) remote JS. A literal reference to one of these domains
# is treated as confirmation in its own right (scheme "cleartext-c2-ref"),
# distinct from decoding 926d6454 out of an inline obfuscated script.
C2_DOMAINS = [
    "nsserdns.beer", "nsserv-bootstru.beer", "nstdcs.beer", "nvbfcdnclaud.beer",
    "olnsclaud.beer", "sbnsdns.beer", "sdhscndnssl.beer", "siteamnsserv.beer",
    "slndcdnclaud.beer", "slngftr.beer", "smetana-js.beer", "smfcdnbb.beer",
    "snccdn-framework.beer", "sns-clauder-cdn.beer", "ssg-cdn.beer",
    "ssjscrybootstrup.beer", "ssns-cdn-ns.beer", "stabcdnvlc.beer",
    "teamcss.beer", "testesclaus.beer", "unacerveza.beer", "vdsinatest.beer",
    "verification-cdn-cloud.beer", "vjscloudjsns.beer", "vnmstokns.beer",
    "vsbnsbootstrup.beer",
]


def check_c2_domain_refs(html_text):
    low = html_text.lower()
    return sorted(d for d in C2_DOMAINS if d in low)


def extract_c2_script_urls(html_text):
    """Find src=/data-src= attribute values (on <script> or <link> tags) whose
    hostname matches one of this operator's known C2 domains -- the cleartext
    lazy-load injection pattern seen on some sites."""
    urls = set()
    for m in re.finditer(r'(?:src|data-src|href)\s*=\s*["\']([^"\']+)["\']', html_text, re.IGNORECASE):
        val = m.group(1)
        low = val.lower()
        for d in C2_DOMAINS:
            if d in low:
                if val.startswith("//"):
                    val = "https:" + val
                elif val.startswith("/"):
                    continue  # relative path, can't be the C2 domain itself
                urls.add(val)
                break
    return urls


STD_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
}


def fetch(host):
    url = f"https://{host}/"
    req = urllib.request.Request(url, headers=STD_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_BYTES)
            data = decompress_body(resp, raw)
            final_url = resp.geturl()
            status = resp.status
            return {"ok": True, "status": status, "final_url": final_url, "body": data}
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(MAX_BYTES)
            data = decompress_body(e, raw)
        except Exception:
            data = b""
        return {"ok": True, "status": e.code, "final_url": url, "body": data, "http_error": True}
    except Exception as e:
        # retry once over http:// if https fails outright
        try:
            url2 = f"http://{host}/"
            req2 = urllib.request.Request(url2, headers=STD_HEADERS)
            with urllib.request.urlopen(req2, timeout=TIMEOUT) as resp:
                raw = resp.read(MAX_BYTES)
                data = decompress_body(resp, raw)
                return {"ok": True, "status": resp.status, "final_url": resp.geturl(), "body": data}
        except Exception as e2:
            return {"ok": False, "error": f"{e} / http fallback: {e2}"}


def fetch_urlscan_result(result_uuid):
    """Fetch the full urlscan.io result JSON (data.requests etc) for a scan.
    This is the ground-truth source: it includes the exact eth_call JSON-RPC
    postData the browser sent to resolve the EtherHiding contract, which is
    far more reliable than trying to decode obfuscated inline JS -- it's the
    literal contract address the injected script queried, straight off the
    wire, regardless of how the injection itself is obfuscated client-side."""
    url = f"https://urlscan.io/api/v1/result/{result_uuid}/"
    headers = {"User-Agent": UA}
    if URLSCAN_API_KEY:
        headers["API-Key"] = URLSCAN_API_KEY
    req = urllib.request.Request(url, headers=headers)
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return {"ok": True, "data": json.loads(resp.read())}
        except Exception as e:
            if attempt == 0:
                time.sleep(2)
                continue
            return {"ok": False, "error": str(e)}


def fetch_urlscan_response_by_hash(resp_hash):
    url = f"https://urlscan.io/responses/{resp_hash}/"
    headers = {"User-Agent": UA}
    if URLSCAN_API_KEY:
        headers["API-Key"] = URLSCAN_API_KEY
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_BYTES)
            data = decompress_body(resp, raw)
            return {"ok": True, "body": data}
    except Exception as e:
        return {"ok": False, "error": str(e)}


ETH_CALL_RE = re.compile(r'"to"\s*:\s*"(0x[0-9a-fA-F]{40})"[^}]*"data"\s*:\s*"(0x[0-9a-fA-F]+)"')
ETH_CALL_RE_ALT = re.compile(r'"data"\s*:\s*"(0x[0-9a-fA-F]+)"[^}]*"to"\s*:\s*"(0x[0-9a-fA-F]{40})"')

# IMPORTANT (found during validation, 2026-07-11): a completely unrelated,
# widespread eth_call pattern pollutes urlscan telemetry across huge numbers
# of random WordPress sites -- selector 0x6d4ce63c ("retrieve()", a extremely
# common Solidity-tutorial/demo getter, likely bundled in some generic
# wallet-connect/crypto-donation plugin/widget) called against addresses that
# turn out to have ZERO on-chain bytecode and ZERO transactions (verified via
# eth_getCode/eth_getTransactionCount on a public Polygon RPC for 9 distinct
# addresses -- all "0x" / 0 tx). These are NOT EtherHiding kit contracts and
# must be excluded, or they produce false "sibling operator" classifications.
# The kit's actual getter selector is 0xb68d1809 (confirmed by decompiling
# the deployed contract bytecode itself, e.g. via eth_getCode on
# 0x926d6454... and 0x9dE78c82... -- both expose b249cd2d/b68d1809/f851a440).
# Only eth_calls with this exact selector are treated as kit-relevant.
KIT_SELECTOR_FULL = "0x" + SELECTOR  # "0xb68d1809"


def extract_eth_calls(result_json):
    """Scan every request's postData for a JSON-RPC eth_call with this kit's
    EXACT getter selector (0xb68d1809) and return (rpc_url, to_address) pairs.
    Calls with any other selector are discarded as unrelated noise (see note
    above -- verified independently, these targets have no on-chain code)."""
    hits = []
    for r in result_json.get("data", {}).get("requests", []):
        req = r.get("request", {}).get("request", {})
        pd = req.get("postData") or ""
        if "eth_call" not in pd or KIT_SELECTOR_FULL not in pd.lower():
            continue
        rpc_url = req.get("url", "")
        to_addr = None
        m = ETH_CALL_RE.search(pd)
        if m and m.group(2).lower().startswith(KIT_SELECTOR_FULL):
            to_addr = m.group(1)
        if not to_addr:
            m2 = ETH_CALL_RE_ALT.search(pd)
            if m2 and m2.group(1).lower().startswith(KIT_SELECTOR_FULL):
                to_addr = m2.group(2)
        if not to_addr:
            try:
                obj = json.loads(pd)
                params = obj.get("params", [{}])
                data_sel = (params[0].get("data") or "") if params else ""
                if data_sel.lower().startswith(KIT_SELECTOR_FULL):
                    to_addr = params[0].get("to")
            except Exception:
                pass
        if to_addr:
            hits.append((rpc_url, to_addr, KIT_SELECTOR_FULL))
    return hits


# This operator's full rotation set: 87 contract addresses controlled by
# deployer wallet 0xb0425bf235a2275735c8c5d668aa0273c65970b9 (deploy-once
# pattern for most, plus setter-call updates on a few persistent ones).
# Independently verified against public Polygon RPC (polygon.drpc.org,
# different endpoint than urlscan used) for 2 sample addresses: both were
# real contract-creation txs from that exact wallet, with the claimed C2
# domain baked into the constructor calldata. Supersedes checking only the
# original seed contract (926d6454...) -- see coordinator correction / on-chain
# investigation notes copied into this directory as bw_operator_contracts_CORRECTED.txt.
try:
    with open("bw_operator_contracts_CORRECTED.txt") as _f:
        THIS_OPERATOR_CONTRACTS = set(
            line.strip().lower() for line in _f if line.strip()
        )
except FileNotFoundError:
    THIS_OPERATOR_CONTRACTS = {TARGET.lower()}  # fallback to seed-only

def classify_contract_address(addr):
    """Compare a contract address against this operator's full 87-address
    rotation set, then the other named sibling operators, then flag anything
    else as a genuinely unlisted/unknown operator on the same kit."""
    if not addr:
        return None
    low = addr.lower().replace("0x", "", 1)
    full = "0x" + low
    if full in THIS_OPERATOR_CONTRACTS:
        return ("confirmed", None)
    if "b6bc9e1d" in low:
        return ("sibling", "xdav (0xB6bC9e1D..., PuppetKing/authorization-cdn-press-enter cluster)")
    if "83833c5d" in low:
        return ("sibling", "Operator #2 (0x83833C5D..., wallet 0xf1940DDB...)")
    if "08207b08" in low:
        return ("sibling", "mamkor.pro campaign (0x08207B08...)")
    return ("sibling-unlisted", addr)


def find_c2_responses_in_result(result_json, c2_domains):
    """Find successful (non-failed) responses in this scan whose URL host
    matches one of our known C2 domains, returning (url, response_hash)."""
    out = []
    for r in result_json.get("data", {}).get("requests", []):
        resp = r.get("response", {})
        if resp.get("failed"):
            continue
        respinfo = resp.get("response", {})
        url = respinfo.get("url", "")
        low = url.lower()
        if any(d in low for d in c2_domains):
            h = resp.get("hash")
            if h:
                out.append((url, h))
    return out


def analyze_via_urlscan_telemetry(host, result_uuids):
    """
    Primary confirmation path: pull the actual urlscan.io scan result(s) for
    this host and look for:
      1. A captured eth_call JSON-RPC request -- the literal on-chain contract
         address the page queried at scan time. This is ground truth,
         independent of any client-side obfuscation scheme.
      2. A successful (non-failed) response body from one of our known C2
         domains -- fetch and decode-scan it the same way we do live pages.
    Returns a result dict compatible with analyze_html()'s shape, or None if
    telemetry yielded nothing usable (caller should fall back to live fetch).
    """
    attempts = []
    for uuid in result_uuids:
        rr = fetch_urlscan_result(uuid)
        if not rr.get("ok"):
            attempts.append({"source": f"urlscan-result:{uuid}", "ok": False, "error": rr.get("error")})
            continue
        result_json = rr["data"]

        eth_calls = extract_eth_calls(result_json)
        for rpc_url, to_addr, selector in eth_calls:
            verdict_kind = classify_contract_address(to_addr)
            attempts.append({"source": f"urlscan-result:{uuid}", "ok": True,
                              "eth_call": {"rpc": rpc_url, "to": to_addr, "selector": selector}})
            if verdict_kind is None:
                continue
            kind, label = verdict_kind
            if kind == "confirmed":
                return {
                    "verdict": "confirmed", "confirmed": True, "sibling": None,
                    "scheme": "onchain-eth_call", "cms": None,
                    "detail": f"eth_call to={to_addr} data={selector} via {rpc_url} (result {uuid})",
                    "attempts": attempts,
                }
            elif kind in ("sibling", "sibling-unlisted"):
                return {
                    "verdict": "sibling", "confirmed": False,
                    "sibling": [label] if kind == "sibling" else [f"unlisted:{label}"],
                    "scheme": "onchain-eth_call", "cms": None,
                    "detail": f"eth_call to={to_addr} data={selector} via {rpc_url} (result {uuid}) -- "
                              f"SAME KIT (selector matches) but DIFFERENT contract, not this operator",
                    "attempts": attempts,
                }

        # No usable eth_call -- check for successfully-loaded C2 response bodies
        c2_resps = find_c2_responses_in_result(result_json, C2_DOMAINS)
        for url, h in c2_resps[:3]:
            br = fetch_urlscan_response_by_hash(h)
            attempts.append({"source": f"urlscan-response:{url}", "ok": br.get("ok"),
                              "error": br.get("error") if not br.get("ok") else None})
            if not br.get("ok"):
                continue
            body = br.get("body", b"")
            try:
                text = body.decode("utf-8", errors="ignore")
            except Exception:
                text = str(body)
            analysis = analyze_html(f"<script>{text}</script>")
            if analysis["verdict"] in ("confirmed", "sibling"):
                analysis["scheme"] = f"urlscan-c2-response({url}):{analysis.get('scheme')}"
                analysis["detail"] = f"decoded stored response body for {url} (result {uuid}) -> {analysis.get('detail')}"
                analysis["attempts"] = attempts
                return analysis

    if attempts:
        return {"verdict": None, "attempts": attempts}  # ran, but inconclusive
    return None


def fetch_url(url):
    """Fetch an arbitrary URL (used for the specific page_url captured by urlscan,
    which may differ from the site root)."""
    req = urllib.request.Request(url, headers=STD_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_BYTES)
            data = decompress_body(resp, raw)
            return {"ok": True, "status": resp.status, "final_url": resp.geturl(), "body": data}
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(MAX_BYTES)
            data = decompress_body(e, raw)
        except Exception:
            data = b""
        return {"ok": True, "status": e.code, "final_url": url, "body": data, "http_error": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def fetch_urlscan_dom(result_uuid):
    """Fetch the DOM snapshot urlscan captured at scan time for a given result UUID.
    This lets us recover the injected script even if the live site has since been
    cleaned up or the injection is cloaked/session-gated."""
    url = f"https://urlscan.io/dom/{result_uuid}/"
    headers = dict(STD_HEADERS)
    if URLSCAN_API_KEY:
        headers["API-Key"] = URLSCAN_API_KEY
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_BYTES)
            data = decompress_body(resp, raw)
            return {"ok": True, "status": resp.status, "body": data}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def find_scripts(html_text):
    """Extract inline <script>...</script> bodies (no src=)."""
    scripts = []
    for m in re.finditer(r"<script([^>]*)>(.*?)</script>", html_text, re.DOTALL | re.IGNORECASE):
        attrs, body = m.group(1), m.group(2)
        if re.search(r"\bsrc\s*=", attrs, re.IGNORECASE):
            continue
        if body.strip():
            scripts.append(body)
    return scripts


def find_base64_blobs(script):
    """Find atob(...) args and long quoted string literals that look base64."""
    blobs = set()
    for m in re.finditer(r"atob\s*\(\s*[\"']([A-Za-z0-9+/=]{40,})[\"']\s*\)", script):
        blobs.add(m.group(1))
    # atob(variable) - find the variable's assigned string nearby
    # generic long base64-looking string literals (40+ chars)
    for m in re.finditer(r"[\"']([A-Za-z0-9+/=]{60,})[\"']", script):
        blobs.add(m.group(1))
    return blobs


def find_var_key_blob_pairs(script):
    """
    Scheme 5: var k=<int>, d="<base64>"; (key cleartext, blob assigned to var,
    decoded elsewhere as base64(d) XOR k). Look for any integer var assignment
    near a base64-like string var assignment within same statement/nearby.
    """
    pairs = []
    # var k=123,d="base64...."
    for m in re.finditer(
        r"var\s+(\w+)\s*=\s*(\d{1,5})\s*,\s*(\w+)\s*=\s*[\"']([A-Za-z0-9+/=]{40,})[\"']",
        script):
        kname, kval, dname, blob = m.groups()
        pairs.append((int(kval), blob))
    # reverse order: var d="base64",k=123
    for m in re.finditer(
        r"var\s+(\w+)\s*=\s*[\"']([A-Za-z0-9+/=]{40,})[\"']\s*,\s*(\w+)\s*=\s*(\d{1,5})",
        script):
        dname, blob, kname, kval = m.groups()
        pairs.append((int(kval), blob))
    # separate statements: var k=123; ... var d="base64...";  (within same script, any int var + any blob var)
    int_vars = re.findall(r"var\s+\w+\s*=\s*(\d{1,5})\s*;", script)
    blob_vars = re.findall(r"var\s+\w+\s*=\s*[\"']([A-Za-z0-9+/=]{40,})[\"']\s*;", script)
    for kval in int_vars:
        for blob in blob_vars:
            pairs.append((int(kval), blob))
    return pairs


def find_sbox_tables(script):
    """Find 256-entry numeric array literals (S-box)."""
    tables = []
    for m in re.finditer(r"\[\s*(\d{1,3}\s*,\s*){200,300}\d{1,3}\s*\]", script):
        nums = [int(x) for x in re.findall(r"\d{1,3}", m.group(0))]
        if len(nums) == 256 and all(0 <= n <= 255 for n in nums):
            tables.append(nums)
    return tables


def check_markers(text):
    """Return set of markers found in text (lowercased check)."""
    low = text.lower()
    found = set()
    for marker in ALL_MARKERS:
        if marker in low:
            found.add(marker)
    return found


def try_decode_b64(blob):
    # normalize padding
    b = blob
    b += "=" * ((4 - len(b) % 4) % 4)
    try:
        return base64.b64decode(b, validate=False)
    except Exception:
        try:
            return base64.b64decode(b + "==", validate=False)
        except Exception:
            return None


def scheme_single_byte_xor(raw_bytes):
    """Brute force single-byte XOR 0-255 using bytes.translate. Return list of (key, decoded_str) hits."""
    hits = []
    for key in range(256):
        table = bytes(((b ^ key) & 0xFF) for b in range(256))
        decoded = raw_bytes.translate(table)
        try:
            text = decoded.decode("utf-8", errors="ignore")
        except Exception:
            continue
        found = check_markers(text)
        if found or any(fm in text for fm in FRAMEWORK_MARKERS) or SELECTOR in text.lower():
            hits.append((key, text, found))
    return hits


def scheme_sub_xor(raw_bytes):
    """
    Brute force ((byte - SUB + 256) & 255) ^ XOR for SUB in 0-255, XOR in 0-255.
    That's 65536 combos over the blob; use translate() per combo (still 65536
    translate calls -- optimize by noting the operation is per-byte and can be
    precomputed as a 256-entry table for each (SUB,XOR) pair).
    To keep this fast, we only run this on blobs already narrowed by size
    (typically a few KB), and short-circuit early if a quick check on a
    prefix doesn't look like plausible JS.
    """
    hits = []
    n = len(raw_bytes)
    if n == 0:
        return hits
    # quick prefix for fast rejection (first 64 bytes)
    prefix = raw_bytes[:64]
    for sub in range(256):
        for xor in range(256):
            table = bytes((((b - sub + 256) & 255) ^ xor) & 0xFF for b in range(256))
            dec_prefix = prefix.translate(table)
            # fast plausibility check: mostly printable ascii
            printable = sum(1 for c in dec_prefix if 32 <= c < 127 or c in (9, 10, 13))
            if printable < len(dec_prefix) * 0.85:
                continue
            decoded = raw_bytes.translate(table)
            try:
                text = decoded.decode("utf-8", errors="ignore")
            except Exception:
                continue
            found = check_markers(text)
            if found or any(fm in text for fm in FRAMEWORK_MARKERS) or SELECTOR in text.lower():
                hits.append((sub, xor, text, found))
    return hits


def scheme_sbox(raw_bytes, table_list):
    hits = []
    for table in table_list:
        tbl = bytes(table)
        decoded = raw_bytes.translate(tbl)
        try:
            text = decoded.decode("utf-8", errors="ignore")
        except Exception:
            continue
        found = check_markers(text)
        if found or any(fm in text for fm in FRAMEWORK_MARKERS) or SELECTOR in text.lower():
            hits.append((text, found))
        # also try inverse table (S-box used for decode means index->value;
        # inverse maps value->index)
        inv = [0] * 256
        for i, v in enumerate(table):
            inv[v] = i
        inv_tbl = bytes(inv)
        decoded2 = raw_bytes.translate(inv_tbl)
        try:
            text2 = decoded2.decode("utf-8", errors="ignore")
        except Exception:
            continue
        found2 = check_markers(text2)
        if found2 or any(fm in text2 for fm in FRAMEWORK_MARKERS) or SELECTOR in text2.lower():
            hits.append((text2, found2))
    return hits


def analyze_html(html_text):
    """Run all decode schemes against one HTML document. Returns a result dict
    (no host/reachability fields -- those are added by the caller)."""
    result = {
        "verdict": "clean",
        "scheme": None,
        "confirmed": False,
        "sibling": None,
        "cms": None,
        "detail": None,
        "c2_domain_refs": [],
        "c2_script_urls": [],
    }

    # CMS detection
    low_html = html_text.lower()
    if "wp-content" in low_html or "wp-includes" in low_html:
        result["cms"] = "WordPress"
    elif "joomla" in low_html:
        result["cms"] = "Joomla"
    elif "drupal" in low_html:
        result["cms"] = "Drupal"
    else:
        result["cms"] = "unknown"

    # 0. Cleartext reference to one of this operator's known C2 domains
    # (e.g. a lazy-loaded <script data-src="https://<c2>/api/css.js?..."> tag).
    # Record it, but don't return immediately -- we still prefer a full
    # contract-content decode if one is available; the caller (analyze_host)
    # will fall back to this if the remote C2 script can't be fetched.
    c2_refs = check_c2_domain_refs(html_text)
    if c2_refs:
        result["c2_domain_refs"] = c2_refs
        result["c2_script_urls"] = sorted(extract_c2_script_urls(html_text))

    # 1. Cleartext check on full html
    found_clear = check_markers(html_text)
    if TARGET in found_clear:
        result["verdict"] = "confirmed"
        result["confirmed"] = True
        result["scheme"] = "cleartext"
        result["detail"] = "target contract substring found in cleartext page"
        return result
    sib_hit = found_clear & set(SIBLINGS.keys())
    if sib_hit:
        result["verdict"] = "sibling"
        result["sibling"] = sorted(sib_hit)
        result["scheme"] = "cleartext"
        result["detail"] = "sibling contract substring found in cleartext page"
        return result

    # gather scripts of interest: containing new Function( or long base64/array literal
    scripts = find_scripts(html_text)
    interesting = [
        s for s in scripts
        if "new function(" in s.lower() or re.search(r"[\"'][A-Za-z0-9+/=]{60,}[\"']", s)
        or re.search(r"\[\s*(\d{1,3}\s*,\s*){50,}", s)
    ]

    tried_blobs = set()
    MAX_BLOBS_PER_HOST = 12
    blobs_tried_count = 0

    # sort scripts so ones containing new Function( (highest signal) go first
    interesting.sort(key=lambda s: (0 if "new function(" in s.lower() else 1, -len(s)))

    for script in interesting:
        if blobs_tried_count >= MAX_BLOBS_PER_HOST:
            break
        # Scheme 4: S-box
        tables = find_sbox_tables(script)
        if tables:
            blobs = find_base64_blobs(script)
            for blob in sorted(blobs, key=len, reverse=True)[:MAX_BLOBS_PER_HOST]:
                if blob in tried_blobs or blobs_tried_count >= MAX_BLOBS_PER_HOST:
                    continue
                tried_blobs.add(blob)
                blobs_tried_count += 1
                raw = try_decode_b64(blob)
                if raw is None:
                    continue
                hits = scheme_sbox(raw, tables)
                for text, found in hits:
                    if TARGET in found:
                        result.update(verdict="confirmed", confirmed=True, scheme="sbox",
                                      detail=f"S-box decode of blob len={len(blob)}")
                        return result
                    sib = found & set(SIBLINGS.keys())
                    if sib:
                        result.update(verdict="sibling", sibling=sorted(sib), scheme="sbox",
                                      detail=f"S-box decode of blob len={len(blob)}")
                        return result

        # Scheme 5: bare var key + blob
        pairs = find_var_key_blob_pairs(script)
        for kval, blob in pairs[:MAX_BLOBS_PER_HOST]:
            if (kval, blob) in tried_blobs or blobs_tried_count >= MAX_BLOBS_PER_HOST:
                continue
            tried_blobs.add((kval, blob))
            blobs_tried_count += 1
            raw = try_decode_b64(blob)
            if raw is None:
                continue
            table = bytes((b ^ (kval & 0xFF)) & 0xFF for b in range(256))
            decoded = raw.translate(table)
            try:
                text = decoded.decode("utf-8", errors="ignore")
            except Exception:
                continue
            found = check_markers(text)
            if TARGET in found:
                result.update(verdict="confirmed", confirmed=True, scheme=f"bare-var-xor(key={kval})",
                              detail=f"blob len={len(blob)}")
                return result
            sib = found & set(SIBLINGS.keys())
            if sib:
                result.update(verdict="sibling", sibling=sorted(sib), scheme=f"bare-var-xor(key={kval})",
                              detail=f"blob len={len(blob)}")
                return result

        # Scheme 2/3: base64 blobs via atob() or long literals -> brute XOR / sub+xor
        blobs = find_base64_blobs(script)
        for blob in sorted(blobs, key=len, reverse=True):
            if blob in tried_blobs or blobs_tried_count >= MAX_BLOBS_PER_HOST:
                continue
            tried_blobs.add(blob)
            blobs_tried_count += 1
            raw = try_decode_b64(blob)
            if raw is None or len(raw) < 8:
                continue

            # Scheme 3: single-byte XOR
            hits = scheme_single_byte_xor(raw)
            for key, text, found in hits:
                if TARGET in found:
                    result.update(verdict="confirmed", confirmed=True, scheme=f"single-byte-xor(key={key})",
                                  detail=f"blob len={len(blob)}")
                    return result
                sib = found & set(SIBLINGS.keys())
                if sib:
                    result.update(verdict="sibling", sibling=sorted(sib), scheme=f"single-byte-xor(key={key})",
                                  detail=f"blob len={len(blob)}")
                    return result

            # Scheme 2: sub+xor (only run on reasonably small blobs to bound cost)
            if len(raw) <= 20000:
                hits2 = scheme_sub_xor(raw)
                for sub, xor, text, found in hits2:
                    if TARGET in found:
                        result.update(verdict="confirmed", confirmed=True,
                                      scheme=f"sub{sub}-xor{xor}",
                                      detail=f"blob len={len(blob)}")
                        return result
                    sib = found & set(SIBLINGS.keys())
                    if sib:
                        result.update(verdict="sibling", sibling=sorted(sib),
                                      scheme=f"sub{sub}-xor{xor}",
                                      detail=f"blob len={len(blob)}")
                        return result

    # framework markers present but no confirmed contract -> note as unconfirmed-suspicious
    if any(fm in html_text for fm in FRAMEWORK_MARKERS) or SELECTOR in low_html:
        result["verdict"] = "unconfirmed-suspicious"
        result["detail"] = "framework/selector marker present but no contract match decoded"
        return result

    result["verdict"] = "clean"
    return result


VERDICT_RANK = {"confirmed": 4, "sibling": 3, "unconfirmed-suspicious": 2, "clean": 1, "unreachable": 0}


def analyze_host(host, page_urls=None, result_uuids=None):
    """
    Confirmation strategy, strongest evidence first:

      0. urlscan.io telemetry for the specific scan(s) that flagged this host:
         - a captured eth_call JSON-RPC request gives the LITERAL on-chain
           contract address the page queried -- ground truth, independent of
           any client-side obfuscation. (See analyze_via_urlscan_telemetry.)
         - failing that, a successful (non-failed) stored response body from
           one of our known C2 domains, decode-scanned the same way as live
           script content.
      1. Live fetch of the specific page URL(s) urlscan saw loading a
         resource from the C2 domain.
      2. Live fetch of the site root.
      3. urlscan.io's stored DOM snapshot from scan time (recovers the
         injection even if the live site was since cleaned up or the
         injection is cloaked to one-time/session visitors).

    IMPORTANT: a bare cleartext reference to one of our known C2 domains
    (e.g. a <script data-src="https://<c2>/..."> tag) is NOT by itself
    sufficient confirmation -- verified against real data, the SAME current
    C2 domain can be reached via DIFFERENT operators' contracts (this kit's
    backend infrastructure appears to be shared/rotated across operators).
    Such cases are reported as unconfirmed-suspicious, not confirmed, unless
    we can independently recover the actual contract address or decoded
    script content.
    """
    best = {
        "host": host,
        "reachable": False,
        "status": None,
        "final_url": None,
        "verdict": "unreachable",
        "scheme": None,
        "confirmed": False,
        "sibling": None,
        "cms": None,
        "detail": None,
        "source": None,
    }
    attempts = []

    # 0. urlscan telemetry first -- ground truth, no live-site dependency
    if result_uuids:
        tele = analyze_via_urlscan_telemetry(host, result_uuids)
        if tele:
            attempts.extend(tele.get("attempts", []))
            if tele.get("verdict") in ("confirmed", "sibling"):
                best.update({k: v for k, v in tele.items() if k != "attempts"})
                best["reachable"] = True
                best["source"] = "urlscan-telemetry"
                best["attempts"] = attempts
                return best

    sources = []
    for pu in (page_urls or []):
        sources.append(("live-page", pu))
    sources.append(("live-root", f"https://{host}/"))
    for uuid in (result_uuids or []):
        sources.append(("urlscan-dom", uuid))

    for kind, ref in sources:
        if kind == "urlscan-dom":
            r = fetch_urlscan_dom(ref)
        else:
            r = fetch_url(ref)

        if not r.get("ok"):
            attempts.append({"source": f"{kind}:{ref}", "ok": False, "error": r.get("error")})
            continue

        best["reachable"] = True
        body_bytes = r.get("body", b"")
        try:
            html_text = body_bytes.decode("utf-8", errors="ignore")
        except Exception:
            html_text = str(body_bytes)

        analysis = analyze_html(html_text)
        attempts.append({
            "source": f"{kind}:{ref}",
            "ok": True,
            "status": r.get("status"),
            "verdict": analysis["verdict"],
            "scheme": analysis.get("scheme"),
        })

        # If this page has a cleartext reference to one of our known C2 domains
        # (e.g. a lazy-loaded <script data-src="https://<c2>/api/css.js?...">)
        # but no local inline decode confirmed the contract, try fetching the
        # remote script itself for a full contract-content decode. If the C2
        # domain is dead (common -- these get sinkholed/taken down), fall back
        # to treating the literal domain reference as confirmation in its own
        # right, since these domains were already validated as this operator's
        # C2 infrastructure before this batch was assigned.
        if analysis.get("c2_script_urls") and analysis["verdict"] not in ("confirmed", "sibling"):
            remote_confirmed = False
            for su in list(analysis["c2_script_urls"])[:3]:
                rr = fetch_url(su)
                attempts.append({"source": f"remote-c2-script:{su}", "ok": rr.get("ok"),
                                  "error": rr.get("error") if not rr.get("ok") else None})
                if rr.get("ok"):
                    body2 = rr.get("body", b"")
                    try:
                        js_text = body2.decode("utf-8", errors="ignore")
                    except Exception:
                        js_text = str(body2)
                    remote_analysis = analyze_html(f"<script>{js_text}</script>")
                    if remote_analysis["verdict"] in ("confirmed", "sibling"):
                        remote_analysis["scheme"] = f"remote-script({su}):{remote_analysis.get('scheme')}"
                        remote_analysis["detail"] = f"fetched remote C2 script {su} -> {remote_analysis.get('detail')}"
                        remote_analysis["cms"] = analysis["cms"]
                        remote_analysis["c2_domain_refs"] = analysis["c2_domain_refs"]
                        remote_analysis["c2_script_urls"] = analysis["c2_script_urls"]
                        analysis = remote_analysis
                        remote_confirmed = True
                        break
            if not remote_confirmed and analysis["verdict"] in ("clean", "unconfirmed-suspicious"):
                # NOTE: NOT auto-confirmed. Verified against real telemetry
                # (see abwmcertified.org), the same current C2 domain can be
                # reached by a DIFFERENT operator's contract -- the kit's
                # backend appears shared/rotated across operators. A bare
                # domain-string reference with no recoverable contract/content
                # is corroborating-but-not-conclusive evidence only.
                analysis = dict(analysis)
                analysis["verdict"] = "unconfirmed-suspicious"
                analysis["confirmed"] = False
                analysis["scheme"] = "cleartext-c2-ref-only"
                analysis["detail"] = (
                    "cleartext reference to assigned C2 domain(s) "
                    + ",".join(analysis["c2_domain_refs"])
                    + " found in page markup, but remote C2 script/content unreachable "
                      "(domain dead/sinkholed, or request failed at scan time) so the "
                      "actual contract could not be independently verified -- domain "
                      "co-occurrence alone is NOT sufficient proof of this operator"
                )

        if VERDICT_RANK[analysis["verdict"]] > VERDICT_RANK[best["verdict"]] or best["status"] is None:
            best.update(analysis)
            best["status"] = r.get("status")
            best["final_url"] = r.get("final_url", ref)
            best["source"] = f"{kind}:{ref}"

        # short-circuit: confirmed is the strongest possible verdict, stop early
        if best["verdict"] == "confirmed":
            break

    best["attempts"] = attempts
    if not best["reachable"]:
        best["error"] = "; ".join(a.get("error", "") for a in attempts if not a.get("ok"))
    return best


def main():
    with open("candidates_raw.json") as f:
        raw = json.load(f)
    candidates = raw["candidates"]

    with open("candidate_hosts.json") as f:
        hosts = json.load(f)

    results = []
    for i, host in enumerate(hosts):
        entries = candidates.get(host, [])
        # distinct page_urls (most specific captured page first), capped
        page_urls = []
        seen_pu = set()
        for e in entries:
            pu = e.get("page_url")
            if pu and pu not in seen_pu:
                seen_pu.add(pu)
                page_urls.append(pu)
        page_urls = page_urls[:5]
        # distinct result uuids, most recent first (entries already roughly time-ordered from urlscan)
        result_uuids = []
        seen_uuid = set()
        for e in entries:
            u = e.get("result_uuid")
            if u and u not in seen_uuid:
                seen_uuid.add(u)
                result_uuids.append(u)
        # NOTE: originally capped at 5. Raised to 20 after finding
        # (2026-07-11) that a host scanned repeatedly by urlscan over weeks
        # (e.g. lightmap.net, 17 separate scans) can have its ONE scan that
        # captured a valid eth_call fall outside the first 5 in raw-query
        # order -- verified by a full re-check that recovered lightmap.net's
        # confirmation from its 16th-oldest scan. See
        # recheck_unconfirmed_full.py for the validation.
        result_uuids = result_uuids[:20]

        # earliest urlscan-seen date across all entries for this host
        seen_dates = sorted(e.get("urlscan_time") for e in entries if e.get("urlscan_time"))
        earliest_seen = seen_dates[0] if seen_dates else None
        pivot_c2s = sorted({e.get("c2") for e in entries if e.get("c2")})

        print(f"[{i+1}/{len(hosts)}] {host} ...", end=" ", flush=True)
        try:
            r = analyze_host(host, page_urls=page_urls, result_uuids=result_uuids)
        except Exception as e:
            r = {"host": host, "reachable": False, "verdict": "error", "error": str(e)}
        r["earliest_urlscan_seen"] = earliest_seen
        r["pivot_c2_domains"] = pivot_c2s
        print(r.get("verdict"), r.get("scheme") or "", r.get("cms") or "", "src=" + str(r.get("source")))
        results.append(r)
        with open("confirm_results.json", "w") as f:
            json.dump(results, f, indent=2, default=str)
        time.sleep(0.3)

    print("\n[*] Done. Saved confirm_results.json")
    counts = {}
    for r in results:
        v = r.get("verdict")
        counts[v] = counts.get(v, 0) + 1
    print("Summary:", counts)


if __name__ == "__main__":
    main()
