# clickfix-finger-lolbin-campaign

Blog post: https://blueteam.cool/posts/clickfix-finger-lolbin-campaign/

## Summary

Roughly twelve hours of endpoint telemetry (June 2026) surfaced 25 suspicious `finger.exe` commands shaped like ClickFix lures. Triaging all 25 revealed three distinct malware families sharing the same TCP/79 delivery vector.

**Family 1 (IronPython / MSI dropper):** The finger response is a 115-line batch script that uses `curl.exe` (renamed to a .com file), downloads IronPython 3.4.2 from GitHub disguised as a .pdf (extracted by `tar.exe`), renames `ipyw32.exe` to a random filename, and runs inline Python. The Python stager fetches Cyrillic-obfuscated Python from a GUID-keyed C2 URL. The Cyrillic substitution obscures a base64 blob that decodes to an XOR decrypt function; 8,912 bytes of x86 shellcode execute via `HeapCreate(HEAP_CREATE_ENABLE_EXECUTE)` + `RtlMoveMemory` + `CFUNCTYPE` inside the IronPython process. The shellcode downloads a ~297 KB encrypted blob; static analysis ends here.

**Family 2 (Python RAT "lspy"):** A four-line PowerShell dropper downloads a 16 MB ZIP from BunnyCDN, extracts portable Python 3.10 + two ChaCha20-encrypted .pyc files to `C:\ProgramData\lspy\`, runs `pythonw.exe install.pyc` windowless, and creates a Startup LNK for persistence. The decrypted RAT provides interactive shell, in-memory shellcode delivery via a named pipe, file drop-and-execute, and self-deletion. C2 is WebSocket/TLS to `staruxasosiska[.]com`.

**Family 3 (linked* staging cluster):** Six "linked*" branded DigitalOcean VPSes ran finger daemons but served no payloads during the triage window. Blank finger queries disclosed active SSH sessions from Tor exit nodes, with login timestamps within 30-72 minutes of domain registration. One server (linkedwiz.com) had a non-idle operator session at triage time.

```
                   ClickFix lure (browser/social engineering)
                              |
                    victim pastes finger command
                              |
                    finger.exe --> TCP/79 --> delivery domain
                              |
            +-----------------+-----------------+
            |                 |                 |
       Family 1          Family 2          Family 3
       (batch)          (PowerShell)     (no payload)
            |                 |
  curl.exe rename     download build.zip
  IronPython .pdf        from BunnyCDN
  tar.exe extract              |
  ipyw32.exe run      extract to ProgramData\lspy\
            |                 |
  C2 fetch Python      pythonw.exe install.pyc
  (GUID-keyed URL)             |
            |         Startup LNK (persistence)
  XOR decrypt shellcode        |
  HeapCreate(execute)  WebSocket/TLS C2
  exec in-process      staruxasosiska[.]com
            |
  ~297 KB encrypted blob
  [static analysis boundary]
```

## What is included

| File | Description |
|------|-------------|
| `iocs.csv` | All IOCs: delivery domains, C2 domains, IPs, URLs, hashes, GUIDs, XOR keys, mutexes, named pipes, directory paths, file name patterns |
| `rule.yar` | Five YARA rules: campaign GUID (near-zero FP), Family 1 batch loader template, Family 1 shellcode XOR keys, Family 2 lspy Python RAT, Family 2 BunnyCDN dropper |
| `sigma-finger-lolbin-process.yml` | Sigma rule: finger.exe execution chain, IronPython batch loader sequence, Family 2 PowerShell/pythonw.exe dropper |
| `sigma-family1-guid-http.yml` | Sigma rule: campaign GUID in proxy/HTTP logs (critical severity, near-zero expected FP) |
| `sigma-family2-lspy-artifacts.yml` | Sigma rule: Family 2 lspy mutex, named pipe, Startup LNK, ProgramData directory |
| `kql.md` | 12 KQL queries for Microsoft Sentinel / Defender XDR covering all families and delivery chain stages |
| `README.md` | This file |

## Coverage notes

### What these detections cover

- Outbound TCP/79 and `finger.exe` execution with `@` in arguments (all families, highest-leverage preventive control)
- Family 1 campaign GUID in HTTP proxy logs (critical fidelity; any hit = victim at stage 2)
- Family 1 batch loader template constants in process/file events
- Family 1 shellcode XOR key bytes in memory dumps or file captures
- Family 2 lspy RAT artifacts: mutex, named pipe, Startup LNK, ProgramData install directory
- Family 2 C2 domain/IP connections (staruxasosiska.com, starayadaet.com)
- Family 2 BunnyCDN staging download (valval-cloud.b-cdn.net/build.zip)
- Family 3 linked* DigitalOcean staging infrastructure (IP and domain lists)

### What these detections do NOT cover

- Family 1 final payload: the ~297 KB encrypted blob downloaded by the shellcode was not decrypted statically. The payload type, capabilities, and persistence mechanisms are unknown. No YARA or detection rule for the final stage is included.
- Family 2 WebSocket C2 traffic content: TLS termination required to inspect C2 protocol body
- Family 3 payloads: no payloads were served during the triage window; if/when the infrastructure activates, new rules will be required
- Novel delivery domains: the GUID and batch template rules catch known-family samples; new delivery domains using a different template would not match `ClickFix_Family1_BatchLoader` until sampled

## False-positive notes

| Rule / Query | FP Guidance |
|---|---|
| `ClickFix_Family1_CampaignGUID` | No known FP sources. GUID is unique to this campaign. |
| `ClickFix_Family1_BatchLoader` | Three-of-five threshold required. Single hits on $s1 (IronPython.3.4.2) may match legitimate IronPython developer installs; raise threshold or combine with finger.exe event. |
| `ClickFix_Family1_ShellcodeXORKeys` | XOR key byte sequences are short (13 and 21 bytes); may hit on arbitrary binary. Combine with Family 1 GUID or batch loader rule for confirmation. |
| `ClickFix_Family2_lspy_PythonRAT` | Any single match on mutex, pipe, or auth key is campaign-confirmed; devpath (`memchacharunpy`) may match if operator's dev machine is in scope -- exclude known developer machines. |
| `ClickFix_Family2_BunnyCDN_Dropper` | `valval-cloud.b-cdn.net` hit alone may be FP if BunnyCDN pull-zone is reused; combine with `lspy` or `install.pyc` string for confirmation. |
| `sigma-finger-lolbin-process.yml` | finger.exe with `@` has near-zero enterprise FP; tar.exe with `.pdf` in args has no known legitimate pattern; ipyw32.exe has no enterprise FP unless IronPython is deployed. |
| `sigma-family1-guid-http.yml` | Near-zero expected FP. Investigate immediately. |
| `sigma-family2-lspy-artifacts.yml` | Near-zero expected FP on mutex/pipe. Startup LNK rule may need folder path tuned for your logging source format. |
| Family 3 Family 3 IPs (AS14061 NJ) | No false positives identified. All six linked* domains are confirmed campaign infrastructure. |

## Confidence

**Overall: HIGH** for Families 1 and 2.

- Family 1: Eight delivery domains served active batch payloads at triage time. Stage 1-3 decoded fully. Shellcode disassembled. Two C2 domains confirmed active. Campaign GUID confirmed present across all samples. XOR keys confirmed per-C2-domain. Stage 4 final payload: unknown (static analysis boundary at the 297 KB encrypted blob).
- Family 2: Delivery domain served active PowerShell dropper. ChaCha20 .pyc files decrypted. RAT source fully recovered. C2 active at triage time. Auth key confirmed shared across two delivery domains.
- Family 3: Infrastructure confirmed (finger daemons live, Tor operator sessions observed). No payloads served during triage window. Medium confidence as campaign infra; activation state unknown.

## Related detections

- [iocs.csv](iocs.csv)
- [rule.yar](rule.yar)
- [sigma-finger-lolbin-process.yml](sigma-finger-lolbin-process.yml)
- [sigma-family1-guid-http.yml](sigma-family1-guid-http.yml)
- [sigma-family2-lspy-artifacts.yml](sigma-family2-lspy-artifacts.yml)
- [kql.md](kql.md)

## Related campaigns

- [finger-lolbin-ironpython](../finger-lolbin-ironpython/) -- Prior investigation (spiorist.com chain); Family 1 ancestor
