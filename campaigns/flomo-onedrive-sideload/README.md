# flomo-onedrive-sideload

Detection artefacts for a ClickFix-delivered DLL sideload campaign using
a trojanised Electron app and a signed OneDrive binary as the loader.

Blog post: https://blueteam.cool/posts/flomo-onedrive-sideload/

---

## Campaign summary

The attacker delivered a ClickFix lure via the Windows Run dialog
(Win+X -> Terminal -> Run) instructing victims to run a PowerShell one-liner.
The one-liner downloaded a ZIP containing a trojanised Electron-based note
app (flomo) from `devltd[.]top`. The ZIP extracted to
`%LOCALAPPDATA%\ExFiles\`, including the app and a sideloading chain.

The sideloading chain used a signed, legitimate `OneDriveLauncher.exe`
(renamed as `Con_Adapter.exe`) dropped to `%TEMP%`. When launched, it
loaded a trojanised `LoggingPlatform.dll` from the same directory instead
of the legitimate OneDrive copy. The DLL decrypted and executed a RAT
payload configured via `signal_config.meta`.

The ClickFix lure also appeared as a fake CAPTCHA page delivering
`finework[.]top`-hosted payloads.

---

## Attack chain

```
ClickFix lure (Win+X terminal or fake CAPTCHA)
  -> PowerShell download: devltd[.]top/flomotg3.zip
  -> ZIP extracts to %LOCALAPPDATA%\ExFiles\
  -> Con_Adapter.exe (= OneDriveLauncher.exe) dropped to %TEMP%
  -> DLL sideload: %TEMP%\LoggingPlatform.dll loaded by Con_Adapter.exe
  -> DLL decrypts config (signal_config.meta / volume1024.conf, AES-CBC)
  -> RAT payload executed; C2 callback to clacndjsvulnarbi[.]beer
```

---

## Key techniques

| ATT&CK | Technique | Notes |
|--------|-----------|-------|
| T1204.002 | User Execution: Malicious File | ClickFix social engineering |
| T1059.001 | PowerShell | Downloader one-liner |
| T1574.002 | DLL Side-Loading | Signed OneDriveLauncher.exe + trojan DLL |
| T1036.005 | Match Legitimate Name or Location | Con_Adapter.exe copies signed OneDrive binary |
| T1027.002 | Software Packing | AES-CBC encrypted RAT config |
| T1071.001 | Web Protocols | HTTPS C2 to clacndjsvulnarbi.beer |

---

## Files in this folder

| File | Purpose |
|------|---------|
| `rule.yar` | Two YARA rules: trojanised LoggingPlatform.dll artifacts; ClickFix/flomo chain file and string pivots |
| `sigma-windowsterminal-powershell-download.yml` | Sigma (process_creation): WindowsTerminal/wt.exe spawning powershell with download args |
| `sigma-onedrive-launcher-nonstandard-path.yml` | Sigma (process_creation): OneDriveLauncher.exe running outside its real install paths |
| `iocs.csv` | Indicators of compromise (defanged network IOCs). NOTE: Con_Adapter.exe sha256 is a signed, legitimate binary -- tag for detection only, not blocking. |
| `kql.md` | Microsoft Sentinel / Defender XDR KQL queries |

---

## Detection notes

- **Con_Adapter.exe sha256 `df6771...` is a signed legitimate Microsoft
  binary.** Do not add it to blocklists. Use the path anomaly (running
  outside its real OneDrive install directory) as the detection signal.
- The ClickFix Win+X vector bypasses detections keyed on
  `explorer.exe -> cmd.exe` by using WindowsTerminal as the grandparent.
  Tune detections around the full grandparent chain, not just direct parents.
- `clacndjsvulnarbi[.]beer` is a strong, high-fidelity domain pivot --
  the TLD choice alone is unusual and unlikely to appear in legitimate traffic.
