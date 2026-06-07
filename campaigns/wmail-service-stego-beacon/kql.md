# KQL Queries -- wmail-service-stego-beacon

Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.

Blog post: https://blueteam.cool/posts/wmail-service-stego-beacon/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. wscript.exe with /e:vbscript against a non-.vbs file

Detects the classic LOLBin move: forcing VBScript interpretation on an
extensionless or GUID-named file. The campaign used this to execute a
GUID-named wrapper without tipping off extension-based content detection.

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\wscript.exe"
| where CommandLine contains "/e:vbscript"
| where not (CommandLine has ".vbs" or CommandLine has ".vbe")
| project TimeGenerated, Computer, SubjectUserName, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "wscript.exe"
| where ProcessCommandLine contains "/e:vbscript"
| where not (ProcessCommandLine has ".vbs" or ProcessCommandLine has ".vbe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp desc
```

---

## 2. Script Block Logging (4104) -- read-decode-execute fingerprint

Detects the payload extraction pattern: ReadAllBytes at an offset,
FromBase64String, ScriptBlock::Create. This triple combination in one
script body is the carrier-read-and-execute fingerprint.

```kql
// Microsoft Sentinel -- Event table (EID 4104)
Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID == 4104
| where RenderedDescription has "ReadAllBytes"
  and RenderedDescription has "FromBase64String"
  and RenderedDescription has "ScriptBlock"
| project TimeGenerated, Computer, UserName, RenderedDescription
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceEvents
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "ReadAllBytes"
  and AdditionalFields has "FromBase64String"
  and AdditionalFields has "ScriptBlock"
| project Timestamp, DeviceName, AccountName, AdditionalFields
| order by Timestamp desc
```

---

## 3. Scheduled task with GUID name running a script host (EID 4698)

Detects creation of a scheduled task whose name matches the bare-GUID
pattern and whose action runs wscript.exe or cscript.exe.

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4698
| where EventData has "wscript.exe" or EventData has "cscript.exe"
| where EventData matches regex @'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'
| project TimeGenerated, Computer, SubjectUserName, EventData
| order by TimeGenerated desc
```

---

## 4. File creation in System32\drivers\ by a non-driver process

Detects writes to System32\drivers\ from anything other than known installer
or Windows Update processes. The carrier drops into a GUID-named subdirectory
under System32\drivers\.

```kql
// Microsoft Defender XDR -- DeviceFileEvents
DeviceFileEvents
| where FolderPath contains @"\Windows\System32\drivers\"
| where not (InitiatingProcessFileName in~ ("TrustedInstaller.exe", "MsMpEng.exe", "WUDFHost.exe"))
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 5. C2 domain and URL-shape pivot

```kql
// Microsoft Sentinel -- DNS or CommonSecurityLog
CommonSecurityLog
| where DestinationHostName has "wmail-service.com"
| project TimeGenerated, DeviceName, SourceIP, DestinationHostName,
          RequestURL, Activity
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceNetworkEvents (URL pattern)
DeviceNetworkEvents
| where RemoteUrl has "wmail-service.com"
  or RemoteUrl matches regex @'/v1/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\?v=DownloadsCounter_'
| project Timestamp, DeviceName, AccountName, RemoteUrl, RemoteIP,
          InitiatingProcessFileName
| order by Timestamp desc
```

---

## 6. Beacon string pivot (SSRS filler in a .sys file)

The filler string "Failed to load dependency Microsoft.AnalysisServices.AdomdClient"
repeated in a .sys file is a strong static pivot -- it should never appear in
a real Windows driver.

```kql
// Microsoft Sentinel -- search across all tables
search "AdomdClient" and "0x80131040"
| where SourceSystem != "OpsManager"
| project TimeGenerated, Type, Computer, _Raw = tostring(pack_all())
| order by TimeGenerated desc
```
