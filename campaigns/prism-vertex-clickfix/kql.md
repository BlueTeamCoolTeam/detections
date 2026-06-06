# KQL Queries -- prism-vertex-clickfix

Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.

Blog post: https://blueteam.cool/posts/prism-vertex-clickfix/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. mshta.exe invoked with a remote URL (near-zero false positive)

Detects `mshta.exe` executing with an HTTP or HTTPS argument. This pattern
has essentially no legitimate enterprise use and is the ClickFix entry point.

**Log source:** SecurityEvent (EID 4688) or DeviceProcessEvents (Defender XDR)

```kql
// Microsoft Sentinel -- SecurityEvent (requires Process Creation auditing)
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\mshta.exe"
| where CommandLine has_any ("http://", "https://")
| project TimeGenerated, Computer, SubjectUserName, NewProcessName,
          CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("http://", "https://")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 2. AMSI bypass in PowerShell Script Block Logging (EID 4104)

Detects cleartext AMSI bypass technique: `.NET` reflection to overwrite
`amsiContext`. Script Block Logging captures this before AMSI is patched,
even when the strings are RC4-encrypted in the source file.

**Log source:** PowerShellOperational (EID 4104) -- requires Script Block
Logging to be enabled (GPO: Computer Configuration -> Windows PowerShell
-> Turn on PowerShell Script Block Logging).

```kql
// Microsoft Sentinel -- Event table (PowerShell operational log)
Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID == 4104
| where RenderedDescription has "amsiContext"
  and RenderedDescription has "WriteInt32"
| project TimeGenerated, Computer, UserName, EventID,
          RenderedDescription
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceEvents (Script Block Logging)
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "amsiContext"
  and AdditionalFields has "WriteInt32"
| project Timestamp, DeviceName, AccountName, ActionType,
          AdditionalFields
| order by Timestamp desc
```

---

## 3. powershell.exe parented to iexplore.exe (IE COM laundering)

Detects PowerShell spawned under `iexplore.exe` via the IE COM moniker.
When IE is not running as a real browser session, this parent relationship
is a reliable anomaly.

**Log source:** SecurityEvent (EID 4688) or DeviceProcessEvents

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4688
| where NewProcessName has "powershell"
| where ParentProcessName endswith "\\iexplore.exe"
| project TimeGenerated, Computer, SubjectUserName, NewProcessName,
          CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName has "powershell"
| where InitiatingProcessFileName =~ "iexplore.exe"
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 4. RC4 key string pivot (BWJFEesMEqRvjQbm)

The RC4 key appears in cleartext in Script Block Logging. A single search
for this string across all telemetry is worth running even without a prior
alert -- it confirms whether this campaign has touched your environment.

```kql
// Microsoft Sentinel -- search across all tables
search "BWJFEesMEqRvjQbm"
| project TimeGenerated, Type, _Raw = tostring(pack_all())
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- process + network events
union DeviceProcessEvents, DeviceNetworkEvents, DeviceEvents
| where ProcessCommandLine contains "BWJFEesMEqRvjQbm"
  or AdditionalFields contains "BWJFEesMEqRvjQbm"
| project Timestamp, DeviceName, AccountName, ActionType,
          ProcessCommandLine, AdditionalFields
| order by Timestamp desc
```

---

## 5. Campaign domain indicators

Block or hunt for the two C2 domains and the stage 5 URL pattern.

**Log source:** Proxy / DNS / DeviceNetworkEvents

```kql
// Microsoft Sentinel -- DNS or proxy logs (CommonSecurityLog)
CommonSecurityLog
| where DestinationHostName has "prism-vertex.com"
  or DestinationHostName has "creativecommunityinfo.art"
| project TimeGenerated, DeviceName, SourceIP, DestinationHostName,
          RequestURL, Activity
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceNetworkEvents
DeviceNetworkEvents
| where RemoteUrl has "prism-vertex.com"
  or RemoteUrl has "creativecommunityinfo.art"
| project Timestamp, DeviceName, AccountName, ActionType,
          RemoteUrl, RemoteIP, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 6. De Morgan XOR signature in Script Block Logging

The JScript decoder uses a De Morgan-rewritten XOR primitive where `-bxor`
never appears literally. The `-bnot(` pattern combined with `-band` in the
same script body is an unusual construct -- legitimate code rarely uses
De Morgan bitwise rewrites.

```kql
// Microsoft Sentinel -- Event table (EID 4104)
Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID == 4104
| where RenderedDescription has "-bnot("
  and RenderedDescription has "-band"
| project TimeGenerated, Computer, UserName, EventID,
          RenderedDescription
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceEvents
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "-bnot("
  and AdditionalFields has "-band"
| project Timestamp, DeviceName, AccountName, ActionType,
          AdditionalFields
| order by Timestamp desc
```
