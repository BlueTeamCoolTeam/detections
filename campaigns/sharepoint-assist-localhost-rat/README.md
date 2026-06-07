# sharepoint-assist-localhost-rat

Detection artefacts for an obfuscated PowerShell localhost HTTP-RAT
with in-memory Win32 API reflection and a hidden HVNC-capable window layer.

Blog post: https://blueteam.cool/posts/sharepoint-assist-localhost-rat/

---

## Campaign summary

The attacker deployed a heavily obfuscated PowerShell script
(`sharepoint-assist.ps1`, 326 KB) staged in `C:\ProgramData\` and
persisted via a scheduled task (`XblGameCachesTask`) disguised as an
Xbox game-cache service entry.

The script opened an `HttpListener` on `127.0.0.1:58172`, exposing two
routes: `/run` accepted arbitrary PowerShell commands and `/window`
accepted JSON-encoded patch/memory operations. The operator accessed
this listener via a separate tunnelling mechanism -- there was no
external C2 address visible in the payload.

The script used `Reflection.Emit` to build an in-memory Win32 API
assembly (`DynWin32_1`) and an `Add-Type` C# class (`W32API`) containing
a `FindPattern` signature scanner, used to locate and patch memory regions
(consistent with HVNC or process injection capability). A single-instance
mutex (`Global\explorer_wide_thumbcache`) guarded against double-execution.

The script ran its console via `conhost.exe --headless` to suppress any
visible window on the desktop.

---

## Attack chain

```
Lure / initial access
  -> sharepoint-assist.ps1 staged to C:\ProgramData\
  -> XblGameCachesTask scheduled task created for persistence (EID 4698)
  -> powershell.exe -file C:\ProgramData\sharepoint-assist.ps1
  -> conhost.exe --headless launched (hidden console)
  -> Global\explorer_wide_thumbcache mutex checked
  -> Reflection.Emit builds DynWin32_1 in-memory assembly
  -> Add-Type builds W32API C# class (FindPattern signature scanner)
  -> HttpListener opens 127.0.0.1:58172
  -> operator connects via external tunnel -> /run (arbitrary PS exec)
                                          -> /window (memory patch / HVNC)
```

---

## Key techniques

| ATT&CK | Technique | Notes |
|--------|-----------|-------|
| T1059.001 | PowerShell | All capability delivered as obfuscated PS |
| T1027.002 | Obfuscated Files or Information | 326 KB heavily obfuscated PS script |
| T1053.005 | Scheduled Task/Job | XblGameCachesTask persistence |
| T1090.001 | Internal Proxy | HttpListener on loopback; operator tunnels in separately |
| T1620 | Reflective Code Loading | Reflection.Emit + Add-Type in-memory Win32 assembly |
| T1055 | Process Injection | FindPattern + VirtualProtectEx memory patcher |
| T1564.003 | Hide Artifacts: Hidden Window | conhost.exe --headless suppresses visible window |

---

## Files in this folder

| File | Purpose |
|------|---------|
| `rule.yar` | YARA rule matching cleartext artifacts (mutex, HttpListener, DynWin32_1, W32API, FindPattern) OR obfuscated on-disk form via size and entropy heuristics |
| `sigma-conhost-headless.yml` | Sigma (process_creation): conhost.exe with --headless argument |
| `sigma-ps-httplistener-localhost.yml` | Sigma (ps_script EID 4104): HttpListener + (RunspaceFactory / VirtualProtectEx / explorer_wide_thumbcache / 127.0.0.1:58172) |
| `iocs.csv` | Indicators of compromise. NOTE: listener address 127.0.0.1:58172 is intentionally NOT defanged -- it is a loopback sentinel, not a routable IOC. |
| `kql.md` | Microsoft Sentinel / Defender XDR KQL queries |

---

## Detection notes

- **No external C2 IOCs.** There are no routable network IOCs to block.
  The operator's external footprint is entirely in the tunnelling mechanism,
  which was not captured. Do not expect DNS or firewall alerts on this one.
- `127.0.0.1:58172` in `iocs.csv` is intentionally not defanged. It is a
  loopback address (allowlisted sentinel) representing the local listener
  endpoint, not a remote C2.
- The `HttpListener` + `RunspaceFactory` combination in a single 4104 event
  is highly specific and should be a high-confidence alert. The individual
  strings are less useful alone (HttpListener appears in legitimate tooling).
- The `XblGameCachesTask` task name is a hard indicator on its own. Any
  creation of a task with that name via EID 4698 warrants immediate
  investigation.
- The YARA entropy/size heuristic (`filesize > 100KB and filesize < 2MB and
  high opcode density`) is intentionally broad. Use it for hunting, not
  alerting. The cleartext-string branch of the YARA rule is the high-fidelity
  variant.
- `conhost.exe --headless` is increasingly used by legitimate developer tooling
  (WSL, VS Code). Tune the sigma rule with a parent process or commandline
  context filter for your environment.
