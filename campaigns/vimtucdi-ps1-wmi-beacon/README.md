# vimtucdi-ps1-wmi-beacon

Detection artefacts for a WMI-delivered PowerShell beacon campaign
with AMSI/ETW bypass and XOR-encrypted command execution.

Blog post: https://blueteam.cool/posts/vimtucdi-ps1-wmi-beacon/

---

## Campaign summary

The attacker used WMI `Win32_Process.Create` to launch PowerShell from
a remote context, making WmiPrvSE.exe the parent process. The PowerShell
payload used reflection to patch `amsi.dll` in-process (setting
`AmsiInitFailed`) and to null the `EtwEventWrite` provider, suppressing
both AMSI inspection and ETW-based Script Block Logging. After bypass,
an XOR-encrypted second stage was fetched from a bare IPv4 over HTTP
and executed in memory.

The loader identified the victim via volume serial number, calculated
a derived bot ID, and sent it in the initial beacon. Scripts were staged
in `C:\ProgramData\` and executed via `powershell.exe -file`. An SCT
file via regsvr32 / a COM object was observed as an alternate execution
path in the same campaign cluster.

---

## Attack chain

```
WMI Win32_Process.Create (remote or local)
  -> powershell.exe parent = WmiPrvSE.exe
  -> AMSI patch: AmsiInitFailed flag set via reflection
  -> ETW patch: EtwEventWrite provider nulled
  -> volume serial read via FileSystemObject.Drives.SerialNumber
  -> bot ID derived; beacon to 77.221.155[.]150 over HTTP port 80
  -> XOR (key: pEctAiwaWzmsNCHIPuGV) decrypt -> IEX in-memory stage 2
  -> stage 2 script staged to C:\ProgramData\ for persistence via task or scheduled exec
  [Alternate path: .sct via regsvr32 -> same PowerShell chain]
```

---

## Key techniques

| ATT&CK | Technique | Notes |
|--------|-----------|-------|
| T1047 | Windows Management Instrumentation | WMI used to launch PowerShell (parent: WmiPrvSE.exe) |
| T1562.001 | Disable or Modify Tools (AMSI) | Reflection-based AmsiInitFailed patch |
| T1562.006 | Indicator Removal on Host (ETW) | ETW provider nulled via reflection |
| T1059.001 | PowerShell | All stages delivered as PowerShell |
| T1132.001 | Data Encoding: Standard Encoding | XOR encryption for stage 2 payload |
| T1082 | System Information Discovery | Volume serial number collection for bot ID |
| T1071.001 | Web Protocols | HTTP beacon to bare IPv4 on port 80 |

---

## Files in this folder

| File | Purpose |
|------|---------|
| `rule.yar` | Two YARA rules: PS XOR/IEX loader (password + IP pivots); SCT WMI launcher strings |
| `sigma-wmiprvse-spawns-powershell.yml` | Sigma (process_creation): WmiPrvSE.exe -> powershell.exe child |
| `sigma-ps-amsiinitfailed-etw-bypass.yml` | Sigma (ps_script EID 4104): amsiInitFailed or etwProvider in script body |
| `iocs.csv` | Indicators of compromise (defanged network IOCs) |
| `kql.md` | Microsoft Sentinel / Defender XDR KQL queries |

---

## Detection notes

- **ETW bypass suppresses 4104 on the local host.** The Script Block
  Logging sigma rule should be treated as a fallback. Forward event logs
  off-host before the attacker can blind local telemetry. The SIEM query
  relying on 4104 data is only effective if log collection is off-host.
- The XOR key `pEctAiwaWzmsNCHIPuGV` and C2 IP `77.221.155.150` are
  high-fidelity, campaign-specific pivots. Both will show up in Script
  Block Logging if AMSI bypass fails or if logs are collected before the
  bypass runs.
- WmiPrvSE.exe spawning powershell.exe is anomalous in most environments
  and has a low false positive rate. It is a good high-confidence alert.
