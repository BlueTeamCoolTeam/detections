# KQL Queries -- finger-lolbin-ironpython

Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.

Blog post: https://blueteam.cool/posts/finger-lolbin-ironpython/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. finger.exe execution (near-zero false positive)

Detects any execution of `finger.exe`. This should essentially never fire in
a modern enterprise environment.

**Log source:** SecurityEvent (EID 4688) or DeviceProcessEvents (Defender XDR)

```kql
// Microsoft Sentinel -- SecurityEvent (requires Process Creation auditing)
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\finger.exe"
| project TimeGenerated, Computer, SubjectUserName, NewProcessName,
          CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "finger.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 2. IronPython interpreter in user AppData

Detects process creation from the IronPython drop directory. The campaign
renames `ipyw32.exe` to a random 3-word filename, so matching the directory
path is more reliable than matching the binary name.

**Log source:** SecurityEvent (EID 4688) or DeviceProcessEvents

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4688
| where NewProcessName contains "\\AppData\\Local\\IronPython"
| project TimeGenerated, Computer, SubjectUserName, NewProcessName,
          CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FolderPath contains @"\AppData\Local\IronPython"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 3. Campaign UUID pivot

The UUID `6d6d2d17-d270-59c6-8b75-df011af08e58` appears in the stage 2
download URL and the shellcode's C2 callback path. A single search across
all log sources for this value is worth running even if you don't believe
this campaign has touched your environment.

```kql
// Microsoft Sentinel -- search across all tables
search "6d6d2d17-d270-59c6-8b75-df011af08e58"
| project TimeGenerated, Type, _Raw = tostring(pack_all())
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- search proxy/network + process logs
union DeviceNetworkEvents, DeviceProcessEvents
| where RemoteUrl contains "6d6d2d17" or ProcessCommandLine contains "6d6d2d17"
| project Timestamp, DeviceName, ActionType, RemoteUrl, ProcessCommandLine
| order by Timestamp desc
```

---

## 4. Outbound TCP/79 (finger protocol)

Most proxy and firewall solutions don't intercept TCP/79. If you have
network flow telemetry, this query is worth running.

**Log source:** AzureNetworkAnalytics_CL, CommonSecurityLog, or equivalent

```kql
// Microsoft Sentinel -- CommonSecurityLog (firewall/proxy)
CommonSecurityLog
| where DestinationPort == 79
| project TimeGenerated, DeviceName, SourceIP, DestinationIP,
          DestinationPort, ApplicationProtocol, Activity
| order by TimeGenerated desc
```

---

## 5. ClickFix lure string in process command line

The lure string `---Verify ----------------press ENTER---` appears in the
`cmd.exe` command line pasted by the victim. This pattern is highly specific
to ClickFix campaigns.

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4688
| where CommandLine contains "---Verify"
| project TimeGenerated, Computer, SubjectUserName, NewProcessName,
          CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR
DeviceProcessEvents
| where ProcessCommandLine contains "---Verify"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          FileName, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 6. Renamed curl.exe executing with URL arguments from AppData

The campaign copies `curl.exe` to `%LocalAppData%\<4-random-words>.com` and
uses it to download IronPython. A `.com` file executing curl-style arguments
from AppData is anomalous.

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FolderPath contains @"\AppData\Local\"
| where FileName endswith ".com"
| where ProcessCommandLine has_any ("-L", "-o", "--output", "https://", "http://")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine
| order by Timestamp desc
```
