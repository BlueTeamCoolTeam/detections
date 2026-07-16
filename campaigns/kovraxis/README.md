# kovraxis

Blog post: https://blueteam.cool/posts/kovraxis/

## Summary

A hidden, execution-policy-bypassed PowerShell one-liner builds a download
domain (`kovraxis[.]com`) from two concatenated string literals, downloads a
3.4MB Go-compiled Windows implant to `%TEMP%\x.exe`, sets
`SEE_MASK_NOZONECHECKS=1` to suppress the Mark-of-the-Web/SmartScreen check,
and runs it.

The implant carries no C2 domain or IP anywhere in its static strings, despite
linking Go's full `net/http`/`crypto/tls`/`encoding/json` stack. Dynamic
analysis showed why: it resolves its real C2 address at runtime via a
dead-drop resolver, polling a throwaway Telegram channel bio and a Level 0
Steam profile display name for a fixed marker string (`gw3n9 <domain>|`).
The recovered domain, `bkv.ambiltogel[.]net`, is Cloudflare-fronted and was
confirmed live via TLS SNI and the implant's own DNS query telemetry.

Once it can reach its C2, the implant force-launches a hidden, GPU-disabled
Edge window to initialize a fresh browser profile, then stages Edge's Login
Data, Cookies, History and Web Data SQLite files in a randomly-named temp
subfolder before reading them back and deleting them within about a second.
Sysmon archive recovery confirmed the file identities; in the observed runs
the harvested databases were empty (fresh VM, no saved data), but the file
set and staging behavior are a confirmed Chromium credential/cookie/autofill
theft capability. Upload volume on the C2 channel far exceeded the size of
the staged files, consistent with an active exfiltration channel rather than
a one-way module fetch.

The implant also carries (but was not observed exercising, across three
real-network detonations) API strings for local account and network share
creation/deletion, logon impersonation, and privilege adjustment.

```
PowerShell (-w hidden -ep bypass)
       |  domain built from 'kovraxis'+'.com'
       v
Invoke-WebRequest -> https://kovraxis[.]com/8845e127.exe -> %TEMP%\x.exe
       |  SEE_MASK_NOZONECHECKS=1 (MOTW/SmartScreen bypass)
       v
Go implant (8845e127.exe) -- no C2 address in static strings
       |  polls dead-drop pages every 2-4s
       |-- Telegram channel bio: "gw3n9 bkv.ambiltogel.net|"
       `-- Steam profile display name: "gw3n9 bkv.kijangturbo88.top|"
       v
C2: bkv.ambiltogel[.]net (Cloudflare-fronted, 104.21.88.153 / 172.67.223.178)
       |
       v
Hidden msedge.exe --no-first-run --disable-gpu about:blank
       |  force-initializes Edge profile
       v
Stage + read-back + delete: Login Data, Cookies, History, Web Data (SQLite)
       |
       v
Upload-heavy traffic to C2 (~12MB up vs ~648KB staged, per one measured run)
```

## What is included

| File | Description |
|------|--------------|
| `iocs.csv` | All indicators: domains, IPs, URLs, hashes, build IDs, file paths, the dead-drop marker pattern |
| `rule.yar` | Two YARA rules: the PowerShell downloader pattern, and the Go implant (build ID, API strings, fake cert CN) |
| `kql.md` | Eight KQL queries for Defender XDR / Sentinel: launcher detection, MOTW-bypass env flag, drop-and-execute, C2 beacon, dead-drop lookups, browser-DB theft, decoy Edge launch, spoofed self-signed cert |
| `README.md` | This file |

No Sigma rules are included in this pack -- the process-creation and
file-event logic above maps more directly to KQL/EDR telemetry for this
campaign than to a Sysmon-based Sigma rule; add one if your environment's
primary telemetry is Sysmon-to-SIEM rather than an EDR advanced-hunting table.

## Coverage notes

### What these detections cover

- The PowerShell launcher's specific command-line shape (hidden window,
  execution-policy bypass, `Invoke-WebRequest` + `UseBasicParsing`)
- The `SEE_MASK_NOZONECHECKS` MOTW-bypass environment flag
- The drop-and-execute pattern to `%TEMP%\x.exe`
- The confirmed C2 domain/subdomain and both known Cloudflare A-records
- The dead-drop resolver lookup pattern (Steam profile + Telegram channel)
- Non-browser access to/creation of Edge profile databases
- The hidden decoy Edge launch that force-initializes the browser profile
- The fake self-signed `anthropic.com` Authenticode certificate, generalized
  to any self-signed cert spoofing a real company CN

### What they do NOT cover

- **The actual exfiltrated content**: TLS was not decrypted in any observed
  run (no `SSLKEYLOGFILE` captured), so the ~12MB-upload-vs-648KB-staged
  discrepancy is not resolved. What is actually sent beyond the five staged
  files is unknown.
- **Local account/share management execution**: the implant carries
  `NetUserAdd`/`NetShareAdd`/impersonation API strings but was never observed
  exercising them across three real-network detonations. The YARA rule
  matches on the strings being present, not on the capability being used --
  treat a hit as "this binary can do this," not "this host was affected by
  it."
- **Initial access / delivery vector**: the analysis started from a bare
  PowerShell command line with no lure, parent process, or delivery context
  supplied. How a real victim would encounter this command is unknown.
- **Domain rotation**: the dead-drop resolver lets the operator repoint C2 by
  editing the Telegram bio or Steam display name at any time, without a new
  binary. `bkv.ambiltogel[.]net` and `kijangturbo88[.]top` are the domains
  confirmed at time of analysis; re-check the dead-drop pages periodically
  for the `gw3n9 ` marker if this campaign resurfaces.

## False-positive notes

**KQL query 1 (launcher)**: Legitimate hidden/scripted PowerShell automation
(scheduled maintenance scripts, RMM tooling) can share the `-w hidden` +
`Invoke-WebRequest` shape. Tune by excluding known automation service
accounts or signed internal script paths.

**KQL query 2 (`SEE_MASK_NOZONECHECKS`)**: This flag has legitimate uses
(some installers and legacy software set it deliberately). Expect very low
volume; investigate rather than auto-block.

**KQL query 5 (dead-drop lookups)**: A raw hit on `steamcommunity.com` or
`telegram.me` URLs will catch normal user browsing if the browser-process
exclusion list isn't complete for your environment's browser set. The
specific profile/channel path narrows this significantly, but confirm the
`InitiatingProcessFileName` exclusion list matches your fleet's installed
browsers.

**KQL query 6 (browser-DB access)**: Backup software, forensic/DFIR tooling,
and browser-sync utilities can legitimately touch these files. Add known-good
process names to the exclusion list for your environment.

**KQL query 8 (spoofed self-signed cert)**: Some internal test-signing or
lab-environment certificates intentionally reuse a company name in the CN for
non-malicious reasons (e.g., a dev testing a code-signing pipeline). Verify
context before treating a hit as malicious.

## Confidence

**Delivery and drop chain: high.** The PowerShell launcher, MOTW-bypass flag,
and payload hash/drop path were confirmed via direct static analysis of the
command line and the fetched binary.

**C2 resolution mechanism: high.** The dead-drop marker pattern was confirmed
directly by viewing both dead-drop pages and matching the shared
`gw3n9 <domain>|` structure. The live C2 connection was confirmed via TLS SNI
inspection and Sysmon DNS Query telemetry across a correctly-scoped capture.

**Browser-data theft capability: high.** The five staged files were recovered
byte-for-byte from a Sysmon FileDelete archive and identified by SQLite table
schema as Edge's own Login Data/Cookies/History/Web Data databases. All
recovered tables were empty in the observed runs (fresh VM profile) -- this
confirms the capability and the collection mechanism, not that any real
credentials were exfiltrated in this analysis.

**Local account/share management capability: probable, not confirmed in
use.** Based on dynamic-resolution API name strings (`LoadLibraryW`/
`GetProcAddress` targets) present in the binary; never observed firing.

**Attribution to a specific actor or group: not claimed.** The recovered
domain names follow a naming convention common to Indonesian gambling-spam
("togel") infrastructure -- a well-documented disposable-domain ecosystem --
but this is a pattern in domain-naming, not an attribution.

## Related detections

- [iocs.csv](iocs.csv) - all indicators
- [rule.yar](rule.yar) - YARA rules
- [kql.md](kql.md) - KQL queries for Defender XDR / Sentinel
