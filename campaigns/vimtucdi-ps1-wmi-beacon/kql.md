# KQL Queries -- vimtucdi-ps1-wmi-beacon

Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.

Blog post: https://blueteam.cool/posts/vimtucdi-ps1-wmi-beacon/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. WmiPrvSE.exe spawning powershell.exe (WMI parent-laundering)

Detects PowerShell created via WMI Win32_Process.Create. The WMI host
(WmiPrvSE.exe) becomes the parent, hiding the true script-host origin.

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4688
| where NewProcessName has "powershell"
| where ParentProcessName endswith "\\WmiPrvSE.exe"
| project TimeGenerated, Computer, SubjectUserName, NewProcessName,
          CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName has "powershell"
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 2. AMSI/ETW bypass strings in Script Block Logging (EID 4104)

Detects the reflection-based AMSI (amsiInitFailed) and ETW (etwProvider)
bypass strings. Note: this loader explicitly nulls ETW to suppress 4104;
forward logs off-host so a local ETW kill cannot blind your SIEM.

```kql
// Microsoft Sentinel -- Event table (EID 4104)
Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID == 4104
| where RenderedDescription has "amsiInitFailed"
  or RenderedDescription has "etwProvider"
  or RenderedDescription has "PSEtwLogProvider"
| project TimeGenerated, Computer, UserName, RenderedDescription
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceEvents
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "amsiInitFailed"
  or AdditionalFields has "etwProvider"
| project Timestamp, DeviceName, AccountName, AdditionalFields
| order by Timestamp desc
```

---

## 3. XOR password and C2 IP pivot

High-fidelity static pivots: XOR key appears in Script Block Logging;
bare IP appears in network telemetry.

```kql
// Microsoft Sentinel -- search all tables
search "pEctAiwaWzmsNCHIPuGV" or "77.221.155.150"
| project TimeGenerated, Type, Computer, _Raw = tostring(pack_all())
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- process + network
union DeviceProcessEvents, DeviceNetworkEvents, DeviceEvents
| where ProcessCommandLine contains "pEctAiwaWzmsNCHIPuGV"
  or RemoteIP == "77.221.155.150"
  or AdditionalFields has "pEctAiwaWzmsNCHIPuGV"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine, RemoteIP
| order by Timestamp desc
```

---

## 4. powershell.exe with -file from C:\ProgramData

Detects scripts launched from the staging folder pattern used by this campaign.

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4688
| where NewProcessName has "powershell"
| where CommandLine has "-file" and CommandLine has @"C:\ProgramData\"
| project TimeGenerated, Computer, SubjectUserName, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

---

## 5. Bare-IP HTTP from powershell.exe (25-second cadence)

The beacon polls a bare IPv4 over HTTP every 25 seconds. Alert on PowerShell
initiating connections to bare IP addresses over port 80.

```kql
// Microsoft Defender XDR -- DeviceNetworkEvents
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where RemotePort == 80
| where RemoteIP matches regex @'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
| where not (RemoteIP startswith "10." or RemoteIP startswith "172.16." or
             RemoteIP startswith "192.168." or RemoteIP == "127.0.0.1")
| project Timestamp, DeviceName, AccountName, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 6. .sct file with regsvr32 (possible Squiblydoo / SCT launcher)

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has ".sct"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp desc
```
