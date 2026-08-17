# KQL Queries -- webdav-over-ssl-loader-family

Microsoft Sentinel / Microsoft Defender XDR queries for this campaign family.

Blog post: https://blueteam.cool/posts/webdav-over-ssl-loader-family/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. Pushd @SSL mount + rundll32 ordinal execution

The core loader pattern across six of the seven incidents: `pushd \\host@SSL\GUID`
followed by `rundll32 <file>,#1`. Near-zero false positives.

**Log source:** SecurityEvent (EID 4688) or DeviceProcessEvents (Defender XDR)

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4688
| where (NewProcessName endswith "\\rundll32.exe" and CommandLine has ",#1")
     or CommandLine has "@SSL\\"
     or CommandLine has "@SSL@443\\"
| project TimeGenerated, Computer, SubjectUserName, NewProcessName,
          CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where (FileName =~ "rundll32.exe" and ProcessCommandLine has ",#1")
     or ProcessCommandLine has "@SSL\\"
     or ProcessCommandLine has "@SSL@443\\"
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 2. LOLBin launcher proxying cmd + rundll32 (delayed-expansion reassembly)

Detects the family's hidden-window launcher rotation: `WmiPrvSE.exe`,
`forfiles.exe`, `conhost.exe --headless`, or `pcalua.exe` spawning `cmd.exe`
with `/v:on` and an `@SSL` UNC path.

**Log source:** SecurityEvent (EID 4688) or DeviceProcessEvents

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\cmd.exe"
| where CommandLine has "/v"
  and CommandLine has "@SSL"
| where ParentProcessName has_any ("WmiPrvSE.exe", "forfiles.exe", "conhost.exe", "pcalua.exe")
| project TimeGenerated, Computer, SubjectUserName, NewProcessName,
          CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has "/v"
  and ProcessCommandLine has "@SSL"
| where InitiatingProcessFileName has_any ("WmiPrvSE.exe", "forfiles.exe", "conhost.exe", "pcalua.exe")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 3. Davclnt.dll DavSetCookie fetch (SERPENTINE#CLOUD sibling)

Near-zero false positives -- this pairing has no legitimate enterprise use.

**Log source:** SecurityEvent (EID 4688) or DeviceProcessEvents

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\rundll32.exe"
| where CommandLine has "davclnt.dll" and CommandLine has "DavSetCookie"
| project TimeGenerated, Computer, SubjectUserName, NewProcessName,
          CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has "davclnt.dll" and ProcessCommandLine has "DavSetCookie"
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 4. WebClient service transitioning to Running

The earliest, cleanest signal in the whole chain -- most workstations never
need the WebDAV redirector, so this service starting at all is worth an alert
on its own.

**Log source:** SecurityEvent (EID 7040, service state change) or DeviceEvents

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 7040
| where NewValue has "WebClient" and NewValue has "running"
| project TimeGenerated, Computer, SubjectUserName, NewValue, OldValue
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents (svchost hosting WebClient)
DeviceProcessEvents
| where FileName =~ "svchost.exe"
| where ProcessCommandLine has "WebClient"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp desc
```

---

## 5. Script Block Logging -- iex/irm/jsDelivr/@SSL

Catches the PowerShell delivery cradle (jsDelivr variants) even when the
loader is base64-obfuscated, since Event ID 4104 logs the decoded body.

**Log source:** Event ID 4104 (PowerShell Operational log)

```kql
// Microsoft Sentinel -- Event (4104 forwarded)
Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID == 4104
| where EventData has_any ("iex", "irm", "cdn.jsdelivr.net/gh/", "@SSL", "Win32_Process")
| project TimeGenerated, Computer, EventData
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceEvents (ScriptBlock)
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("iex", "irm", "cdn.jsdelivr.net/gh/", "@SSL", "Win32_Process")
| project Timestamp, DeviceName, AccountName, ActionType, AdditionalFields
| order by Timestamp desc
```

---

## 6. Outbound to public blockchain RPC (EtherHiding pivot)

A workstation talking to a BSC-testnet RPC endpoint is not doing anything a
normal user does. See the linked `betwanaa-boroo-webdav-etherhiding` campaign
folder for the deeper EtherHiding contract/wallet dataset (incident 4).

**Log source:** Proxy logs / CommonSecurityLog or DeviceNetworkEvents

```kql
// Microsoft Sentinel -- CommonSecurityLog
CommonSecurityLog
| where DestinationHostName has "publicnode.com"
| project TimeGenerated, DeviceName, SourceIP, DestinationHostName,
          RequestURL, Activity
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceNetworkEvents
DeviceNetworkEvents
| where RemoteUrl has "publicnode.com" or RemoteHostname has "publicnode.com"
| project Timestamp, DeviceName, AccountName, ActionType,
          RemoteUrl, RemoteHostname, RemoteIP,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 7. RunMRU registry pivot (ClickFix paste evidence)

`HKCU\...\Explorer\RunMRU` is a genuinely underused surface for this delivery
style -- the pasted command lands there before execution.

**Log source:** Registry auditing / Sysmon Event ID 13, or DeviceRegistryEvents

```kql
// Microsoft Defender XDR -- DeviceRegistryEvents
DeviceRegistryEvents
| where RegistryKey has @"Explorer\RunMRU"
| where RegistryValueData has_any ("@SSL", "pushd", ",#1", "conhost --headless")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData
| order by Timestamp desc
```

---

## 8. SERPENTINE#CLOUD duckdns C2 pivot (incident 7)

```kql
// Microsoft Defender XDR -- DeviceNetworkEvents
DeviceNetworkEvents
| where RemoteUrl has "duckdns.org" or RemoteHostname has "duckdns.org"
| where RemoteIP in ("12.202.180.133", "12.202.180.105")
     or ipv4_is_match(RemoteIP, "12.202.176.0/21")
| project Timestamp, DeviceName, AccountName, ActionType,
          RemoteUrl, RemoteHostname, RemoteIP,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
