# KQL Queries -- sharepoint-assist-localhost-rat

Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.

Blog post: https://blueteam.cool/posts/sharepoint-assist-localhost-rat/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. Script Block Logging (4104) -- HttpListener + runspace + Win32 API

The three components appear in the same 4104 event when the obfuscated PS
executes: the HttpListener class, RunspaceFactory (in-memory runspace), and
VirtualProtectEx or FindPattern (the Win32 reflection helpers).

```kql
// Microsoft Sentinel -- Event table (EID 4104)
Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID == 4104
| where RenderedDescription has "HttpListener"
  and (RenderedDescription has "RunspaceFactory"
       or RenderedDescription has "VirtualProtectEx"
       or RenderedDescription has "explorer_wide_thumbcache"
       or RenderedDescription has "127.0.0.1:58172")
| project TimeGenerated, Computer, UserName, RenderedDescription
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceEvents
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "HttpListener"
  and (AdditionalFields has "RunspaceFactory"
       or AdditionalFields has "VirtualProtectEx"
       or AdditionalFields has "FindPattern")
| project Timestamp, DeviceName, AccountName, AdditionalFields
| order by Timestamp desc
```

---

## 2. conhost.exe with --headless (hidden console)

The RAT launches a console host in headless mode to suppress the visible
window. Any use of --headless on conhost is unusual outside of known tooling.

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "\\conhost.exe"
| where CommandLine contains "--headless"
| project TimeGenerated, Computer, SubjectUserName, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

```kql
// Microsoft Defender XDR -- DeviceProcessEvents
DeviceProcessEvents
| where FileName =~ "conhost.exe"
| where ProcessCommandLine contains "--headless"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 3. powershell.exe owning a LISTEN socket on loopback (Sysmon EID 3)

Sysmon network connection events surface when a process opens a listening
socket. powershell.exe with Initiated == false and a loopback address is the
localhost-RAT fingerprint.

```kql
// Microsoft Sentinel -- Sysmon Event ID 3 (Network Connection)
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 3
| where RenderedDescription has "powershell.exe"
  and RenderedDescription has "Initiated=false"
  and (RenderedDescription has "127.0.0.1" or RenderedDescription has "0.0.0.0")
| project TimeGenerated, Computer, UserName, RenderedDescription
| order by TimeGenerated desc
```

---

## 4. XblGameCachesTask scheduled task creation (EID 4698)

The persistence mechanism is a task disguised as a legitimate Xbox game-cache
task. Creation of any task with this name is a hard indicator.

```kql
// Microsoft Sentinel -- SecurityEvent
SecurityEvent
| where EventID == 4698
| where EventData contains "XblGameCachesTask"
| project TimeGenerated, Computer, SubjectUserName, EventData
| order by TimeGenerated desc
```

---

## 5. payload hash pivot

```kql
// Microsoft Defender XDR -- DeviceFileEvents + DeviceProcessEvents
union DeviceFileEvents, DeviceProcessEvents
| where SHA256 == "f1767aaebb55347153c56e21adbf3a41e48663d139279ec8e3b1f1be1db63a53"
  or MD5 == "59978abc44e9aa790767baf54122f455"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath,
          SHA256, ProcessCommandLine
| order by Timestamp desc
```

---

## 6. Global\explorer_wide_thumbcache mutex (named mutex pivot)

Sysmon EID 17 (Pipe Created) does not capture named mutexes directly, but
the mutex name shows up in 4104 logs as part of the class definition. A
string search across DeviceEvents surfaces the name.

```kql
// Microsoft Defender XDR -- DeviceEvents
DeviceEvents
| where AdditionalFields has "explorer_wide_thumbcache"
| project Timestamp, DeviceName, AccountName, ActionType, AdditionalFields,
          InitiatingProcessFileName
| order by Timestamp desc
```

---

## 7. Broad pivot -- Add-Type with C# class containing Win32 P/Invoke

Detects any in-session P/Invoke assembly defining FindPattern or kernel32
imports via reflection. Broader than this campaign but catches the
technique class.

```kql
// Microsoft Defender XDR -- DeviceEvents
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "Add-Type"
  and AdditionalFields has "DllImport"
  and (AdditionalFields has "kernel32" or AdditionalFields has "VirtualProtect")
| project Timestamp, DeviceName, AccountName, AdditionalFields
| order by Timestamp desc
```
