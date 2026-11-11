# KQL Queries -- quantai-fake-youtube-netsupport-rat
Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.
Blog post: https://blueteam.cool/posts/quantai-fake-youtube-netsupport-rat/
> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

## 1. Network: lure, dropper and gateway domains

```kql
let domains = dynamic(["quantai.io","chartsgpt.com","sonosarcsounds.com","sonosarcsounds.net"]);
DeviceNetworkEvents
| where Timestamp > ago(120d)
| where RemoteUrl has_any (domains) or RemoteIP == "45.91.202.58" or RemotePort == 2084
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
```

## 2. ClickFix paste: PowerShell from Explorer with irm and iex on the command line

```kql
DeviceProcessEvents
| where Timestamp > ago(120d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where InitiatingProcessFileName in~ ("explorer.exe","WindowsTerminal.exe")
| where ProcessCommandLine has "irm" and ProcessCommandLine has "iex"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

This only catches the variant where the whole command goes into the Run dialog. This campaign's page tells the
user to open PowerShell first and paste into the console, which leaves a bare `powershell.exe` command line.
Use script block logging (query 3) for that.

## 3. Dropper strings in PowerShell script blocks

```kql
DeviceEvents
| where Timestamp > ago(120d)
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("Dio=", "-pkim", "-pico", "-pfafa", "-pbro", "$gagarik", "$xaxaxar")
| project Timestamp, DeviceName, InitiatingProcessAccountName, AdditionalFields
```

## 4. NetSupport client outside Program Files

```kql
DeviceProcessEvents
| where Timestamp > ago(120d)
| where ProcessVersionInfoOriginalFileName =~ "client32.exe"
| where FolderPath !startswith @"C:\Program Files"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

## 5. NetSupport config or licence written under a user profile

```kql
DeviceFileEvents
| where Timestamp > ago(120d)
| where FileName in~ ("client32.ini","NSM.LIC","PCICL32.DLL")
| where FolderPath has @"\Users\"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName,
          InitiatingProcessCommandLine
```

## 6. icacls deny plus Owner Rights grant under LocalAppData

```kql
DeviceProcessEvents
| where Timestamp > ago(120d)
| where FileName =~ "icacls.exe"
| where ProcessCommandLine has @"\AppData\Local\"
| where ProcessCommandLine has "/deny" or ProcessCommandLine has "*S-1-3-4"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

## 7. Startup shortcut pointing at the RAT folders

```kql
DeviceFileEvents
| where Timestamp > ago(120d)
| where FolderPath has @"\Start Menu\Programs\Startup"
| where FileName in~ ("service.lnk","stservice.lnk")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName,
          InitiatingProcessFolderPath
```
