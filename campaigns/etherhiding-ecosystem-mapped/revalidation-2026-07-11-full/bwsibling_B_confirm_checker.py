#!/usr/bin/env python3
"""
Part B/C -- BW-sibling live re-confirmation checker.

Adapted from reproduction-log/06_bwsibling_confirmed_site_validator.py. The
decode logic (5 obfuscation schemes: cleartext, atob+sub-then-XOR, plain
single-byte XOR, 256-byte S-box, bare `var k=N,d="..."` assignment) is
reused as-is. The one deliberate change from the original script is the
confirmation marker set: the original checker's inline analyze_html() only
ever tested decoded content against ONE contract prefix (the seed contract,
926d6454), even though a separate on-chain-telemetry code path in the same
file already knew about the full 87-address set -- a documented methodology
gap that undercounts true positives. This script tests decoded content
against ALL 87 of this operator's contract-address prefixes (first 8 hex
chars after "0x", verified collision-free against each other and against
the 3 known sibling-operator prefixes -- see console check in this
directory's transcript).

Usage:
    python bwsibling_B_confirm_checker.py <hosts_file> <output_json> [--workers N]

<hosts_file> is a plain text file, one hostname per line.
Writes a JSON list of per-host result dicts to <output_json>, and prints a
running summary to stdout.
"""
import base64
import concurrent.futures
import gzip
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import zlib

# Relaxed SSL context used ONLY as a fallback when the default (verifying)
# context raises a cert error. Many of these compromised small-business sites
# have expired/self-signed/hostname-mismatched TLS certs unrelated to the
# EtherHiding injection itself -- treating an expired cert as "unreachable"
# would silently undercount confirmations on sites that are otherwise live.
INSECURE_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
INSECURE_CTX.check_hostname = False
INSECURE_CTX.verify_mode = ssl.CERT_NONE

try:
    import brotli
except ImportError:
    brotli = None
try:
    import zstandard
except ImportError:
    zstandard = None

CONTRACTS_FILE = r"C:\Users\bob\Documents\Tools\BlueTeamCoolTeam\detections\campaigns\etherhiding-ecosystem-mapped\family_a_bwsibling_all_contracts.txt"
C2_DOMAINS_FILE = r"C:\Users\bob\Documents\Tools\BlueTeamCoolTeam\detections\campaigns\etherhiding-ecosystem-mapped\family_a_bwsibling_all_c2_domains.txt"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
TIMEOUT = 25
MAX_BYTES = 20 * 1024 * 1024  # 20MB cap

STD_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
}

with open(CONTRACTS_FILE, "r", encoding="utf-8") as _f:
    THIS_OPERATOR_ADDRS = [line.strip().lower() for line in _f if line.strip()]
assert len(THIS_OPERATOR_ADDRS) == 87, f"expected 87 contracts, got {len(THIS_OPERATOR_ADDRS)}"

# First 8 hex chars after "0x" for each of the 87 addresses -- verified
# collision-free against each other and against the 3 sibling prefixes below.
THIS_OPERATOR_PREFIXES = set(a.replace("0x", "", 1)[:8] for a in THIS_OPERATOR_ADDRS)
assert len(THIS_OPERATOR_PREFIXES) == 87

SIBLINGS = {
    "b6bc9e1d": "Operator 1 / xdav (0xB6bC9e1D...)",
    "83833c5d": "Operator 2 (0x83833C5D...)",
    "0c7cb01c": "Operator 3 (0x0C7Cb01C...)",
}
ALL_MARKERS = list(THIS_OPERATOR_PREFIXES) + list(SIBLINGS.keys())

FRAMEWORK_MARKERS = ["__BW_MODE_RUN__", "site_repair_state", "CONTRACT_ADDRESS", "FUNCTION_SELECTOR"]
SELECTOR = "b68d1809"

with open(C2_DOMAINS_FILE, "r", encoding="utf-8") as _f:
    C2_DOMAINS = [line.strip().lower() for line in _f if line.strip()]
assert len(C2_DOMAINS) == 90


def decompress_body(resp, raw_body):
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
        body = raw_body
    return body


def fetch_url(url, _retried_insecure=False):
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
    except (ssl.SSLError, urllib.error.URLError) as e:
        is_cert_issue = isinstance(e, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(e) or "certificate" in str(e).lower()
        if is_cert_issue and not _retried_insecure and url.startswith("https://"):
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT, context=INSECURE_CTX) as resp:
                    raw = resp.read(MAX_BYTES)
                    data = decompress_body(resp, raw)
                    return {"ok": True, "status": resp.status, "final_url": resp.geturl(), "body": data,
                            "insecure_ssl_fallback": True}
            except Exception as e2:
                return {"ok": False, "error": f"{e} / insecure-ssl retry: {e2}"}
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def fetch_host(host):
    r = fetch_url(f"https://{host}/")
    if r.get("ok"):
        return r
    return fetch_url(f"http://{host}/")


def check_c2_domain_refs(html_text):
    low = html_text.lower()
    return sorted(d for d in C2_DOMAINS if d in low)


def extract_c2_script_urls(html_text):
    urls = set()
    for m in re.finditer(r'(?:src|data-src|href)\s*=\s*["\']([^"\']+)["\']', html_text, re.IGNORECASE):
        val = m.group(1)
        low = val.lower()
        for d in C2_DOMAINS:
            if d in low:
                if val.startswith("//"):
                    val = "https:" + val
                elif val.startswith("/"):
                    continue
                urls.add(val)
                break
    return urls


def find_scripts(html_text):
    scripts = []
    for m in re.finditer(r"<script([^>]*)>(.*?)</script>", html_text, re.DOTALL | re.IGNORECASE):
        attrs, body = m.group(1), m.group(2)
        if re.search(r"\bsrc\s*=", attrs, re.IGNORECASE):
            continue
        if body.strip():
            scripts.append(body)
    return scripts


def find_base64_blobs(script):
    blobs = set()
    for m in re.finditer(r"atob\s*\(\s*[\"']([A-Za-z0-9+/=]{40,})[\"']\s*\)", script):
        blobs.add(m.group(1))
    for m in re.finditer(r"[\"']([A-Za-z0-9+/=]{60,})[\"']", script):
        blobs.add(m.group(1))
    return blobs


def find_var_key_blob_pairs(script):
    pairs = []
    for m in re.finditer(
        r"var\s+(\w+)\s*=\s*(\d{1,5})\s*,\s*(\w+)\s*=\s*[\"']([A-Za-z0-9+/=]{40,})[\"']",
        script):
        kname, kval, dname, blob = m.groups()
        pairs.append((int(kval), blob))
    for m in re.finditer(
        r"var\s+(\w+)\s*=\s*[\"']([A-Za-z0-9+/=]{40,})[\"']\s*,\s*(\w+)\s*=\s*(\d{1,5})",
        script):
        dname, blob, kname, kval = m.groups()
        pairs.append((int(kval), blob))
    int_vars = re.findall(r"var\s+\w+\s*=\s*(\d{1,5})\s*;", script)
    blob_vars = re.findall(r"var\s+\w+\s*=\s*[\"']([A-Za-z0-9+/=]{40,})[\"']\s*;", script)
    for kval in int_vars:
        for blob in blob_vars:
            pairs.append((int(kval), blob))
    return pairs


def find_sbox_tables(script):
    tables = []
    for m in re.finditer(r"\[\s*(\d{1,3}\s*,\s*){200,300}\d{1,3}\s*\]", script):
        nums = [int(x) for x in re.findall(r"\d{1,3}", m.group(0))]
        if len(nums) == 256 and all(0 <= n <= 255 for n in nums):
            tables.append(nums)
    return tables


def check_markers(text):
    low = text.lower()
    found = set()
    for marker in ALL_MARKERS:
        if marker in low:
            found.add(marker)
    return found


def try_decode_b64(blob):
    b = blob
    b += "=" * ((4 - len(b) % 4) % 4)
    try:
        return base64.b64decode(b, validate=False)
    except Exception:
        try:
            return base64.b64decode(b + "==", validate=False)
        except Exception:
            return None


def _confirmed_or_sibling(found):
    """Given a set of found markers, return ('confirmed', None) if any of
    this operator's 87 prefixes hit, ('sibling', [labels]) if a sibling
    prefix hit (and no operator prefix hit), else None."""
    op_hit = found & THIS_OPERATOR_PREFIXES
    if op_hit:
        return ("confirmed", sorted(op_hit))
    sib_hit = found & set(SIBLINGS.keys())
    if sib_hit:
        return ("sibling", sorted(SIBLINGS[s] for s in sib_hit))
    return None


def scheme_single_byte_xor(raw_bytes):
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
    hits = []
    n = len(raw_bytes)
    if n == 0:
        return hits
    prefix = raw_bytes[:64]
    for sub in range(256):
        for xor in range(256):
            table = bytes((((b - sub + 256) & 255) ^ xor) & 0xFF for b in range(256))
            dec_prefix = prefix.translate(table)
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

    low_html = html_text.lower()
    if "wp-content" in low_html or "wp-includes" in low_html:
        result["cms"] = "WordPress"
    elif "joomla" in low_html:
        result["cms"] = "Joomla"
    elif "drupal" in low_html:
        result["cms"] = "Drupal"
    else:
        result["cms"] = "unknown"

    c2_refs = check_c2_domain_refs(html_text)
    if c2_refs:
        result["c2_domain_refs"] = c2_refs
        result["c2_script_urls"] = sorted(extract_c2_script_urls(html_text))

    # 1. Cleartext check on full html
    found_clear = check_markers(html_text)
    verdict = _confirmed_or_sibling(found_clear)
    if verdict:
        kind, label = verdict
        result["verdict"] = kind
        result["confirmed"] = kind == "confirmed"
        result["sibling"] = None if kind == "confirmed" else label
        result["scheme"] = "cleartext"
        result["detail"] = f"marker(s) {sorted(found_clear)} found in cleartext page"
        return result

    scripts = find_scripts(html_text)
    interesting = [
        s for s in scripts
        if "new function(" in s.lower() or re.search(r"[\"'][A-Za-z0-9+/=]{60,}[\"']", s)
        or re.search(r"\[\s*(\d{1,3}\s*,\s*){50,}", s)
    ]

    tried_blobs = set()
    MAX_BLOBS_PER_HOST = 12
    blobs_tried_count = 0

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
                    verdict = _confirmed_or_sibling(found)
                    if verdict:
                        kind, label = verdict
                        result.update(verdict=kind, confirmed=(kind == "confirmed"),
                                      sibling=None if kind == "confirmed" else label,
                                      scheme="sbox", detail=f"S-box decode of blob len={len(blob)}")
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
            verdict = _confirmed_or_sibling(found)
            if verdict:
                kind, label = verdict
                result.update(verdict=kind, confirmed=(kind == "confirmed"),
                              sibling=None if kind == "confirmed" else label,
                              scheme=f"bare-var-xor(key={kval})", detail=f"blob len={len(blob)}")
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

            hits = scheme_single_byte_xor(raw)
            for key, text, found in hits:
                verdict = _confirmed_or_sibling(found)
                if verdict:
                    kind, label = verdict
                    result.update(verdict=kind, confirmed=(kind == "confirmed"),
                                  sibling=None if kind == "confirmed" else label,
                                  scheme=f"single-byte-xor(key={key})", detail=f"blob len={len(blob)}")
                    return result

            if len(raw) <= 20000:
                hits2 = scheme_sub_xor(raw)
                for sub, xor, text, found in hits2:
                    verdict = _confirmed_or_sibling(found)
                    if verdict:
                        kind, label = verdict
                        result.update(verdict=kind, confirmed=(kind == "confirmed"),
                                      sibling=None if kind == "confirmed" else label,
                                      scheme=f"sub{sub}-xor{xor}", detail=f"blob len={len(blob)}")
                        return result

    if any(fm in html_text for fm in FRAMEWORK_MARKERS) or SELECTOR in low_html:
        result["verdict"] = "unconfirmed-suspicious"
        result["detail"] = "framework/selector marker present but no contract match decoded"
        return result

    result["verdict"] = "clean"
    return result


VERDICT_RANK = {"confirmed": 4, "sibling": 3, "unconfirmed-suspicious": 2, "clean": 1, "unreachable": 0}


def analyze_host(host):
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
    }

    r = fetch_host(host)
    if not r.get("ok"):
        best["error"] = r.get("error")
        return best

    best["reachable"] = True
    best["status"] = r.get("status")
    best["final_url"] = r.get("final_url")
    body_bytes = r.get("body", b"")
    try:
        html_text = body_bytes.decode("utf-8", errors="ignore")
    except Exception:
        html_text = str(body_bytes)

    analysis = analyze_html(html_text)

    # cleartext C2 domain reference but no confirmed decode yet -> try fetching
    # the remote C2 script itself for a full contract-content decode.
    if analysis.get("c2_script_urls") and analysis["verdict"] not in ("confirmed", "sibling"):
        remote_confirmed = False
        for su in list(analysis["c2_script_urls"])[:3]:
            rr = fetch_url(su)
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
        if not remote_confirmed and analysis["verdict"] in ("clean", "unconfirmed-suspicious") and analysis["c2_domain_refs"]:
            analysis = dict(analysis)
            analysis["verdict"] = "unconfirmed-suspicious"
            analysis["confirmed"] = False
            analysis["scheme"] = "cleartext-c2-ref-only"
            analysis["detail"] = (
                "cleartext reference to assigned C2 domain(s) "
                + ",".join(analysis["c2_domain_refs"])
                + " found in page markup, but remote C2 script/content unreachable or "
                  "did not decode to a contract match -- domain co-occurrence alone is "
                  "NOT sufficient proof of this operator"
            )

    best.update(analysis)
    best["status"] = r.get("status")
    best["final_url"] = r.get("final_url")
    return best


def main():
    if len(sys.argv) < 3:
        print("usage: bwsibling_B_confirm_checker.py <hosts_file> <output_json> [--workers N]")
        sys.exit(1)
    hosts_file = sys.argv[1]
    out_json = sys.argv[2]
    workers = 12
    if "--workers" in sys.argv:
        idx = sys.argv.index("--workers")
        workers = int(sys.argv[idx + 1])

    with open(hosts_file, "r", encoding="utf-8") as f:
        hosts = [line.strip() for line in f if line.strip()]

    print(f"Loaded {len(hosts)} hosts from {hosts_file}. Checking against 87 operator contract "
          f"prefixes + {len(SIBLINGS)} sibling prefixes. Workers={workers}.", flush=True)

    results = {}
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_host = {ex.submit(analyze_host, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(future_to_host):
            h = future_to_host[fut]
            try:
                r = fut.result()
            except Exception as e:
                r = {"host": h, "reachable": False, "verdict": "unreachable", "error": str(e)}
            results[h] = r
            done += 1
            print(f"[{done}/{len(hosts)}] {h} -> {r.get('verdict')} "
                  f"{r.get('scheme') or ''} sibling={r.get('sibling')}", flush=True)

    # preserve input order in the output list
    ordered = [results[h] for h in hosts]

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(ordered, f, indent=2, default=str)

    counts = {}
    for r in ordered:
        v = r.get("verdict")
        counts[v] = counts.get(v, 0) + 1
    print("\nSummary:", counts)
    print(f"Wrote {out_json}")


if __name__ == "__main__":
    main()
