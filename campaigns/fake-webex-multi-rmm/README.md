# fake-webex-multi-rmm

Blog post: https://blueteam.cool/posts/fake-webex-multi-rmm/

## Summary

A victim downloaded what they believed was a Webex meeting installer from a
GitHub Releases URL. The delivered file was a custom, Authenticode-signed Go
remote-access tool the developer named "Rocky RMM" in its own build manifest --
no packing, no obfuscation, signed with a legitimately-issued SSL.com
code-signing certificate for a shell company ("Space Solar Technologies LLC")
created ten days before the build.

Pulling the thread on the delivery account (`gees11111`, a GitHub account
roughly ninety minutes older than its only real repository) surfaced a live
staging directory with eight release tags publishing four independent
delivery chains to four different remote-access tools, all across a 48-hour
window with real double-digit download counts:

```
Leg 1   Rocky RMM      Custom Go RAT, websocket C2, Startup-folder VBScript
                       persistence. Uses its own command channel to push a
                       second, genuine ScreenConnect client (dual-RMM
                       tradecraft).
Leg 2a  ScreenConnect  Batch file -> UAC self-elevate -> PowerShell download
                       from a Cloudflare R2 bucket -> msiexec /qn.
Leg 2b  ScreenConnect  Signed, unmodified Progress EnableLoopback.exe
                       sideloads a malicious FirewallAPI.dll (MinGW crypter,
                       single-byte XOR key 0xB8) that drops and runs a
                       decrypted ScreenConnect MSI.
Leg 2c  ScreenConnect  Direct genuine ScreenConnect installer, no loader
                       tricks at all.
Leg 3   Level.io       Inno Setup installer -> plaintext PowerShell
                       Invoke-WebRequest -> msiexec /qn, enrolling into the
                       attacker's Level.io tenant via a hardcoded API key.
                       Zero obfuscation; the "malware" here is entirely the
                       enrollment key.
Leg 4   Agta Backup    WiX MSI dropping 5 unsigned .NET 8 single-file RAT
        Agent          components masquerading as security software
                       (Credential Guard.exe, Dell.Virus.Guard.exe, etc.).
                       Hidden self-installed service, hVNC hidden-desktop
                       browser hijack, keylogger with browser-URL context,
                       Chromium-profile theft, scheduled-task self-heal
                       guardian.
```

Legs 2a, 2b, and 2c all converge on the exact same ScreenConnect relay
(`167.94.158.48:8041`), instance ID (`d08195f142b8bd3b`), and operator label
("Popepagascreen") -- strong evidence these are one operator running three
loader variants against the same back end, not three unrelated actors.

The Agta C2 panel's operator console additionally ships 19 named
"quick-command" scripts. Two of them go beyond remote access into victim
captivity: a "Disable power options" command that hides/blocks the power
button, sleep, shutdown, and logoff paths (down to redirecting the Windows
slide-to-shut-down gesture via an Image File Execution Options debugger
hijack), and a "Lock Wi-Fi (stay online)" command that installs a persistent
watchdog forcing Wi-Fi reconnection roughly once a second while hiding the
network toggle. This tooling shape is consistent with a live, hands-on-
keyboard social-engineering operation that needs the victim to stay put and
stay connected, not a quiet long-term implant.

## What is included

| File | Description |
|------|-------------|
| `iocs.csv` | Domains, IPs, URLs, hashes, service/task/pipe names, cert serial, enrollment keys/secrets across all 4 legs |
| `rule.yar` | 5 YARA rules: Rocky RMM Go RAT, generic VBScript-shortcut persistence template, FirewallAPI.dll sideload crypter, ScreenConnect shared-relay config strings, Agta .NET RAT components |
| `sigma-fake-webex-msi-silent-install.yml` | Process creation: PowerShell-downloaded MSI silently installed via `msiexec /qn` (shared Leg 2a/Leg 3 pattern) |
| `sigma-rocky-rmm-startup-persistence.yml` | Two rules: `cscript //nologo *.vbs` persistence write, and the literal `RockyRMMClient.lnk` file-creation event |
| `sigma-agta-hidden-service-and-victim-lockout.yml` | Two rules: Agta hidden-service install / scheduled-task guardian / secedit privilege-removal, and the IFEO `SlideToShutDown.exe` registry hijack |
| `kql.md` | 9 KQL query groups for Microsoft Sentinel / Defender XDR covering all 4 legs plus the operator victim-lockout scripts |
| `README.md` | This file |

## Coverage notes

### What these detections cover

- **Rocky RMM Go RAT** (Leg 1): YARA `RMM_RockyRMM_Go_Client` (module path, C2 URL, persistence VBScript, console strings all recovered verbatim from the binary), Sigma `sigma-rocky-rmm-startup-persistence.yml`, KQL queries 1 and 6. High confidence -- the C2 URL and Startup-folder filename are unique to this tool.
- **Generic VBScript shortcut-persistence template** (`RMM_Generic_VBScript_Shortcut_Persistence_Template`): broader hunt in case the same builder is reused under a different module name in a future sample. Will also match any other tool using an identical `CreateShortcut` template -- expect some noise if used standalone.
- **ScreenConnect sideload chain** (Leg 2b): YARA `webex_firewallapi_sideload_screenconnect_loader` -- the exported function names plus either the dropped filename or the XOR-decrypt instruction sequence. High confidence.
- **Shared ScreenConnect relay/instance** (Legs 2a/2b/2c): YARA `screenconnect_relay_167_94_158_48` matches the exact relay+port and instance-ID config strings embedded in any ScreenConnect client pointed at this operator's infrastructure. KQL query 2.
- **PowerShell-to-MSI silent install** (Legs 2a and 3): Sigma `sigma-fake-webex-msi-silent-install.yml`, KQL query 5. This is a technique-level detection -- it will also catch other, unrelated fake-installer campaigns using the same shape, which is a feature, not noise.
- **Level.io enrollment abuse** (Leg 3): KQL query 4, hunting on the enrollment key and the (legitimate) Level.io download domain together. The key is campaign-specific and rotates per operator, so this exact key will age out -- the query pattern (any `LEVEL_API_KEY=` in a process command line outside a documented IT enrollment) is the durable hunt.
- **Agta Backup Agent components** (Leg 4): YARA `AgtaBackupAgent_DotNet_RAT_Components` (authored from confirmed-present strings in the CLR metadata -- C2 secret, checkin path, service-install/watchdog flags, named pipes, masquerade names; not a rule recovered verbatim from the sample, built from the analysis), Sigma `sigma-agta-hidden-service-and-victim-lockout.yml`, KQL queries 3 and 7.
- **Victim-lockout operator scripts**: Sigma's `secedit`/USER_RIGHTS selection and the dedicated IFEO rule, plus KQL query 8. These are genuinely novel artifacts -- an IFEO debugger redirect on `SlideToShutDown.exe` and mass `Policies\Explorer` registry writes have no legitimate reason to occur together outside this tooling.

### What these detections do NOT cover

- **The inner ScreenConnect MSI's own telemetry** once installed -- these rules detect the delivery and sideload mechanics, not ScreenConnect's own subsequent remote-access session activity. Pair with your organization's existing RMM-inventory and session-auditing controls.
- **Agta's hVNC video stream and DXGI screen-capture traffic** -- no network-layer signature for the stream protocol itself was recovered; only the named pipes and C2 checkin endpoint are covered.
- **The exact live command/response JSON schema between Agta components and the C2** -- not captured (C2 was not interactively contacted during analysis; static analysis only).
- **Future infrastructure** -- the GitHub account, R2 bucket, and both C2 IPs were live at analysis time (2026-09-05) but are trivially replaceable. Treat the IOC list as a snapshot, not a permanent blocklist, and prioritize the technique-level Sigma rules for durability.
- **How the victim initially reached the GitHub Releases page** -- phishing email, fake support call, or malvertising would all be consistent with the artifacts, but none is confirmed. No detection here covers the initial lure delivery.

## False-positive notes

| Rule / Query | FP risk | Tuning suggestion |
|---|---|---|
| `RMM_RockyRMM_Go_Client` | Low -- C2 URL and Startup-folder filename are unique | None required |
| `RMM_Generic_VBScript_Shortcut_Persistence_Template` | Medium -- matches the technique, not just this tool | Expect hits on other builders using the identical template; use as a hunt lead, not an auto-block |
| `webex_firewallapi_sideload_screenconnect_loader` | Low -- export names + drop name/XOR sequence combination is specific | None required |
| `screenconnect_relay_167_94_158_48` | Low -- exact relay+instance-ID string match | Will not catch a redeployed instance on a new IP/instance ID |
| `AgtaBackupAgent_DotNet_RAT_Components` | Low-Medium -- masquerade names alone (`$masq*`) could theoretically collide with unrelated tools; rule requires them paired with a service/watchdog/desktop indicator | Do not lower the 2-of-masq + behavioral-indicator requirement |
| Sigma MSI silent-install | Medium -- legitimate SCCM/Intune/GPO silent MSI deploys use the same `msiexec /qn` shape | Tune by ParentImage (management-agent parents vs. user-launched PowerShell) |
| Sigma Rocky RMM cscript persistence | Medium -- some legitimate logon scripts use `cscript //nologo` | Filter by ParentImage; Rocky RMM's cscript is spawned directly by the payload EXE, not explorer/wscript |
| Sigma RockyRMMClient.lnk file-creation | Low -- filename is unique | None required |
| Sigma Agta hidden-service/task | Medium -- some legitimate backup/endpoint agents self-install hidden services | Correlate against known-good vendor and a change record |
| Sigma IFEO SlideToShutDown.exe | Low -- no legitimate use case identified | None required |

## Confidence

**High** for Rocky RMM, the ScreenConnect sideload chain, and the shared-relay/instance detections -- all built from strings and config values recovered verbatim from static analysis, with no packing or obfuscation to work around.

**High** for the Level.io and batch/R2 delivery detections -- both chains are plaintext, fully recovered end-to-end.

**Medium-High** for the Agta Backup Agent YARA rule -- the underlying capabilities (C2 endpoint, service-install flags, named pipes) were confirmed from unobfuscated .NET CLR metadata, but the rule itself is newly authored from those findings rather than lifted verbatim from an existing detection artifact.

**Medium** for the victim-lockout Sigma rules -- the scripts themselves were fully recovered from the operator panel's own JavaScript bundle, but these detections were not tested against a live execution; tune the `secedit`/USER_RIGHTS selection if it proves noisy in environments with frequent legitimate security-baseline deployments.

## Related detections

- [iocs.csv](iocs.csv)
- [rule.yar](rule.yar)
- [sigma-fake-webex-msi-silent-install.yml](sigma-fake-webex-msi-silent-install.yml)
- [sigma-rocky-rmm-startup-persistence.yml](sigma-rocky-rmm-startup-persistence.yml)
- [sigma-agta-hidden-service-and-victim-lockout.yml](sigma-agta-hidden-service-and-victim-lockout.yml)
- [kql.md](kql.md)
