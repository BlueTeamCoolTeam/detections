# clickfix-captcha-code-lol

Blog post: https://blueteam.cool/posts/clickfix-captcha-code-lol/

## Summary

ClickFix campaign delivering a five-layer RC4+GZip PowerShell stager from `captcha-code[.]lol`.
Victims land on a fake captcha page and are prompted to paste a cmd command that downloads
and executes the loader via `curl | powershell -WindowStyle Hidden`.

The loader peels five nested layers, each with the same RC4+GZip+IEX wrapper. The final
decoded stage checks for ~50 analysis/VM processes before beaconing victim metadata to `/m`
and receiving the next payload via `iex`. Domain-joined and WORKGROUP victims are routed
separately (tags `BCDA222` and `ABCD111`).

The WORKGROUP branch drops an 8 MB Rust infostealer (`update.exe`) that force-installs a
malicious extension across Chrome, Edge, Opera, Brave, Vivaldi, and Arc by tampering with
`Secure Preferences` HMAC fields. It also enumerates all active Windows logon sessions via
`LsaEnumerateLogonSessions`/`LsaGetLogonSessionData` (secur32.dll) and performs full AD
user/group recon via `NetUserEnum`/`NetGroupEnum` (netapi32.dll). Persists via Run key
`ibrowser`. C2 at `94.154.32[.]21:8080`.

A second branch (Flask server at `87.232.123[.]174:80`) drops a custom PIC shellcode loader
(`data.bin`) with a multiplier-83 API hash resolver. The inner payload is runtime-encrypted
at offset 0x4000+; family not recovered statically.

The C2 panel (Lunex, port 8000) is a bilingual EN/RU React SPA with full browser injection,
domain spoofing, remote WebSocket browser control, and screenshot capabilities.
OSINT on the infrastructure confirmed panel capabilities at time of analysis. Panel created 2026-06-04.

```
Lure            captcha-code[.]lol -> fake captcha -> user pastes command
Launcher        cmd /v:on /k -> wildcard obfuscation -> curl | powershell -w hidden
Staging         Five nested RC4+gzip layers, each IEX'd in memory (main.ps1)
Recon           50-tool sandbox check; host fingerprint beacon to /m
Routing         WORKGROUP tag (ABCD111) vs domain tag (BCDA222) -> different payload
Payload A       Rust infostealer update.exe: force extension, LSA session enum, AD recon, persist
Payload B       data.bin: custom PIC shellcode loader, inner payload runtime-encrypted
```

## What is included

| File | Description |
|------|-------------|
| `iocs.csv` | 22 indicators: domains, IPs, SHA256 hashes, filenames, registry key, URLs, campaign GUID, API key, build path |
| `rule.yar` | 5 YARA rules: PS loader, anti-analysis list, Rust stealer, Lunex panel JS bundle, shellcode loader |
| `sigma-clickfix-ps-loader.yml` | PowerShell Script Block (4104) matches for RC4 PRGA, GZip, beacon domain, campaign tags |
| `sigma-clickfix-delivery-chain.yml` | Process creation: cmd -> curl -> hidden PowerShell delivery pattern |
| `sigma-stealer-run-key.yml` | Registry: ibrowser Run key persistence (Sysmon Event ID 13) |
| `kql.md` | 8 KQL queries for Microsoft Sentinel / Defender XDR |
| `README.md` | This file |

## Coverage notes

### What these detections cover

- **RC4+GZip loader** (all 5 layers): YARA `ClickFix_CaptchaCode_PS_Loader`, Sigma `sigma-clickfix-ps-loader.yml`, KQL queries 1 and 2. The RC4 PRGA string and beacon domain are distinctive; low FP expected.
- **Anti-analysis process check**: YARA `ClickFix_CaptchaCode_AntiAnalysis_List` -- matches decoded scripts; the tool names are obfuscated in the original loader, so this rule fires on the decoded output only.
- **ClickFix delivery chain** (cmd -> curl -> hidden PS): Sigma `sigma-clickfix-delivery-chain.yml`, KQL query 2. May match other ClickFix variants with similar delivery.
- **Rust stealer** (`update.exe`): YARA `Stealer_Rust_chapter_BrowserExt` -- high confidence on the combination of `$dev + $mz + $lsa`. Individual strings ($chk, $reg) may appear in other tools.
- **Stealer C2 network traffic**: KQL query 3 (IP-based; pivot to API path `/api/v1/checkin` for broader coverage).
- **LSA session enumeration** (workstation context): KQL query 7 -- requires module load telemetry; tune the exclusion list for your environment.
- **AD enumeration via NetAPI**: KQL query 8 -- volume-based hunt; threshold may need tuning.
- **Run key persistence** (`ibrowser`): YARA string `$reg`, Sigma `sigma-stealer-run-key.yml`, KQL query 4. High confidence; `ibrowser` is not a legitimate application name.
- **Lunex C2 panel** (JS bundle): YARA `Lunex_Panel_JS_Bundle` -- 4-of-6 condition; useful for hunting during IR on the panel server itself or in web proxy logs capturing the JS bundle.
- **Shellcode loader** (`data.bin`): YARA `Shellcode_Loader_Multiplier83_Hash` -- the disk magic header `$disk_hdr` is highly specific; `$hash83 + $lcase` catches the decoded/mapped loader in memory.

### What these detections do NOT cover

- **Enterprise branch payload** (domain-joined branch, `BCDA222` routing): the C2 returned a 520 error during analysis. The payload delivered to domain-joined victims is unknown. These detections do not cover it.
- **Inner shellcode payload** (loaded by `data.bin`): the inner payload at offset 0x4000+ is runtime-encrypted with entropy 7.998. Family not recovered statically. No detection rules for the inner payload are included.
- **Extension behavior post-install**: once the malicious browser extension is running, its JavaScript-level activity (cookie exfil, page injection, screenshot) is not covered by these host-based rules. Browser extension monitoring (DLP, CASB) would be required.
- **Telegram bot token**: the token is provisioned per-victim at checkin and rotates across victims. KQL query 5 hunts on the API domain pattern rather than a specific token.
- **Future C2 infrastructure**: the stage-7 domains (`9sxbhphss8kiyk2[.]top`, `hfpfhy7zytroclo[.]top`, `v4bdhuudd0n353v[.]top`) were dead/NXDOMAIN at time of analysis; the operator may stand up replacements.

## False-positive notes

| Rule / Query | FP risk | Tuning suggestion |
|---|---|---|
| `ClickFix_CaptchaCode_PS_Loader` ($rc4) | Low -- RC4 PRGA expression is specific | None required |
| `ClickFix_CaptchaCode_PS_Loader` ($gz alone) | Medium -- GZip class is common in PS | Require $gz + another $rc4 or $iex match |
| `ClickFix_CaptchaCode_AntiAnalysis_List` | Medium -- individual tool names appear in legitimate security scripts | 4-of-6 threshold is already conservative; do not lower |
| `Stealer_Rust_chapter_BrowserExt` ($chk alone) | Medium -- `/api/v1/checkin` path may appear in other tools | Rule requires $mz at 0 + 2 of ($dev,$pref,$reg,$chk,$lsa); full condition is low FP |
| Sigma delivery chain (hidden PS) | Medium -- enterprise automation uses `-WindowStyle Hidden` | Tune by parent process or network connection to known bad domain |
| KQL query 8 (bulk AD enum) | Medium -- LDAP queries from management tools | Tune exclusion list; lower threshold only in environments with poor visibility |

## Confidence

**Overall: High** for loader-stage detections; **Medium** for payload-stage detections.

Loader: the RC4+GZip chain was fully decoded statically across all five layers. The beacon strings, PRGA expression, and campaign tags are confirmed present in the decoded output. YARA and Sigma rules were tested against the known-good decodes.

Payload A (Rust stealer): binary analysed directly; import table, strings, and config block confirmed. ABE bypass strings (`IElevator`, `CryptUnprotectData`) were initially reported but retracted -- confirmed absent from the binary after re-examination (substring matches in TLS cipher names). YARA rule uses confirmed-present strings only.

Payload B (shellcode loader): only the transport layer (XOR 0x3B) was recovered. Inner payload family unknown. YARA rule covers the loader wrapper only.

Enterprise branch: not captured. No detections for enterprise-branch payload.

## Related detections

- [iocs.csv](iocs.csv)
- [rule.yar](rule.yar)
- [sigma-clickfix-ps-loader.yml](sigma-clickfix-ps-loader.yml)
- [sigma-clickfix-delivery-chain.yml](sigma-clickfix-delivery-chain.yml)
- [sigma-stealer-run-key.yml](sigma-stealer-run-key.yml)
- [kql.md](kql.md)
