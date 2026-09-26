#!/usr/bin/env python3
"""
Independent re-validation of the Agta Backup panel set.

Written because the original agta_comprehensive_validation.py output
(agta_validation_results.json) was found to contain at least four systematic
collection bugs:

  1. server_header captured for 1 of 77 records (real value: IIS on every
     panel sampled by hand)
  2. ssl_* fields null for all 77 (certificates were never collected at all)
  3. version recorded as null for 10 live panels that do in fact serve
     /AgtaBackupAgent.version (they return a *different* version string)
  4. bundle_hash null for at least one panel that does serve a bundle

This script re-derives every claim from scratch. Read-only: GET requests to
the panel root and the version endpoint, plus a TLS handshake for the
certificate. No authentication attempts, no POSTs, no payload downloads.

Classification:
  LIVE        domain resolves publicly AND the host serves the Agta panel
  VHOST_ONLY  host serves the Agta panel when the Host header is forced,
              but the domain does not resolve publicly (not reachable by a
              victim; infrastructure still provisioned)
  DEAD        neither

Usage:  python revalidate_agta.py [input.json] [output.json]
"""
import json
import re
import socket
import ssl
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

TIMEOUT = 8
BUNDLE_RE = re.compile(r"index-[A-Za-z0-9_-]+\.js")
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.S)


def resolve(domain):
    """Public DNS resolution. Returns list of A records, or [] if it fails."""
    try:
        infos = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def curl(domain, ip, path="/"):
    """GET with Host header and TLS SNI both pinned to `domain`, routed to `ip`."""
    cmd = [
        "curl", "-sk", "--max-time", str(TIMEOUT),
        "--resolve", f"{domain}:443:{ip}",
        "-w", "\n__HTTPCODE__%{http_code}",
        f"https://{domain}{path}",
    ]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=TIMEOUT + 5).stdout
    except Exception:
        return None, ""
    if "__HTTPCODE__" not in out:
        return None, ""
    body, _, code = out.rpartition("\n__HTTPCODE__")
    try:
        return int(code.strip()), body
    except ValueError:
        return None, body


def get_cert(domain, ip):
    """Pull issuer O/CN and validity window via SNI handshake."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                der = ss.getpeercert(binary_form=True)
        # Parse with openssl for a stable text rendering
        p = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout",
             "-issuer", "-subject", "-dates"],
            input=der, capture_output=True, timeout=TIMEOUT,
        )
        txt = p.stdout.decode("utf-8", "replace")
        out = {}
        for line in txt.splitlines():
            if line.startswith("issuer="):
                out["issuer"] = line[7:].strip()
            elif line.startswith("subject="):
                out["subject"] = line[8:].strip()
            elif line.startswith("notBefore="):
                out["not_before"] = line[11:].strip()
            elif line.startswith("notAfter="):
                out["not_after"] = line[10:].strip()
        return out or None
    except Exception:
        return None


def headers(domain, ip):
    cmd = ["curl", "-sk", "-I", "--max-time", str(TIMEOUT),
           "--resolve", f"{domain}:443:{ip}", f"https://{domain}/"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=TIMEOUT + 5).stdout
    except Exception:
        return {}
    h = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            h[k.strip().lower()] = v.strip()
    return h


def check(rec):
    domain, ip = rec["domain"], rec["ip"]
    res = {
        "domain": domain,
        "recorded_ip": ip,
        "recorded_status": rec.get("status"),
        "asn": rec.get("asn"),
        "country": rec.get("country"),
    }
    dns = resolve(domain)
    res["dns_resolves"] = bool(dns)
    res["dns_answers"] = dns
    res["dns_matches_recorded_ip"] = ip in dns

    code, body = curl(domain, ip, "/")
    res["http_status"] = code
    title_m = TITLE_RE.search(body or "")
    res["title"] = title_m.group(1).strip() if title_m else None
    res["is_agta"] = bool(res["title"] and "Agta Backup" in res["title"])
    bundles = BUNDLE_RE.findall(body or "")
    res["bundle_hash"] = bundles[0] if bundles else None
    res["html_bytes"] = len(body or "")

    vcode, vbody = curl(domain, ip, "/AgtaBackupAgent.version")
    res["version_http_status"] = vcode
    v = (vbody or "").strip()
    res["version"] = v if (vcode == 200 and re.fullmatch(r"[0-9.]{3,12}", v)) else None

    if res["is_agta"]:
        h = headers(domain, ip)
        res["server_header"] = h.get("server")
        res["x_powered_by"] = h.get("x-powered-by")
        res["has_csp"] = "content-security-policy" in h
        res["x_frame_options"] = h.get("x-frame-options")
        res["cert"] = get_cert(domain, ip)
    else:
        res["server_header"] = res["x_powered_by"] = None
        res["has_csp"] = False
        res["x_frame_options"] = None
        res["cert"] = None

    if res["is_agta"] and res["dns_resolves"]:
        res["status"] = "LIVE"
    elif res["is_agta"]:
        res["status"] = "VHOST_ONLY"
    else:
        res["status"] = "DEAD"
    return res


def main():
    inp = sys.argv[1] if len(sys.argv) > 1 else "agta_validation_results.json"
    outp = sys.argv[2] if len(sys.argv) > 2 else "agta_revalidation_results.json"
    records = json.load(open(inp, encoding="utf-8"))
    print(f"re-validating {len(records)} records ...", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=12) as ex:
        results = list(ex.map(check, records))
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_file": inp,
        "record_count": len(results),
        "results": results,
    }
    json.dump(payload, open(outp, "w", encoding="utf-8"), indent=2)
    print(f"wrote {outp}", file=sys.stderr)


if __name__ == "__main__":
    main()
