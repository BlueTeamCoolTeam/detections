# KQL Queries -- agta-strikes-again

Microsoft Sentinel / Microsoft Defender XDR queries for this campaign.
Blog post: https://blueteam.cool/posts/agta-strikes-again/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

## 1. Connections to known Agta panel hosts

All 65 operator-controlled addresses confirmed live on 2026-09-09. The
Cloudflare edge address fronting one panel is deliberately excluded.

```kql
let AgtaIPs = dynamic([
  "5.56.25.124","31.57.147.133","31.76.42.170","38.92.47.244",
  "38.240.36.164","38.240.37.26","38.240.37.64","38.247.130.218",
  "45.43.27.27","45.61.145.136","45.61.145.226","45.61.170.180",
  "45.86.230.42","45.143.146.205","66.235.172.4","72.51.59.172",
  "77.67.88.40","91.92.41.12","96.126.176.22","104.249.131.195",
  "104.250.238.248","104.255.228.25","107.149.8.237","135.136.143.12",
  "135.136.144.116","135.136.145.136","135.136.149.81","135.136.158.125",
  "136.0.82.187","142.147.97.151","144.172.93.65","144.172.93.181",
  "144.172.101.170","144.172.102.191","144.172.106.146","144.172.107.178",
  "146.70.41.134","153.52.168.167","153.52.175.85","153.52.175.88",
  "154.127.53.175","155.254.99.248","172.81.61.190","172.81.63.140",
  "172.81.130.133","172.86.119.25","172.245.80.3","173.195.100.71",
  "184.174.20.16","189.12.226.77","191.101.130.42","192.177.111.82",
  "192.177.111.202","192.187.126.252","194.156.79.65","198.23.201.147",
  "199.101.198.90","199.101.198.132","207.189.19.40","207.189.30.118",
  "209.87.166.236","212.43.147.93","216.126.224.247","217.216.91.58",
  "217.217.97.184"
]);
DeviceNetworkEvents
| where RemoteIP in (AgtaIPs)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
```

## 2. DNS lookups for known Agta panel domains

All 66 domains confirmed serving the panel on 2026-09-09.

```kql
let AgtaDomains = dynamic([
  "abrooferguys.com","americansoftwareinc.co","anuoagentworkingbacking.top",
  "backupplanetwealthagta.top","biowinntech.com","blessingsbe.top",
  "bookthinkers.us","bootbackup.com","bringgitonnorzone.sbs",
  "bubblesteam.top","cacgreatchallange.org","cashyejrudga.live",
  "cheapmovellc.com","childofwhho.top","connectnowfast.top",
  "connectprivae.top","countrygeek.top","criopifileeworking.top",
  "datavaseffhjurd.top","dronscorep.top","electomm.sbs","emef.info",
  "emmshopllc.wiki","emsafetoproceedtaward.top","evobasin.info",
  "fresestarsgsd.top","gsop.top","installapp.cc","interrview.com",
  "jimmycafeetoptea.top","llgoldassociates.com","magicislanding.lol",
  "oakssmiiledesign.com","palnetworkingleup.top","piejaholoop.org",
  "planetdoubleearthonly.top","planetearthcleantop.top",
  "planetvocalfortesttheteas.cyou","planetvocalfortheteas.cyou",
  "planetwealthonlycleancoffe.top","planetwealthonlycleantea.top",
  "planetworkingade.top","planetworkingclassrewor.top",
  "planetworkingcleaningall.top","planetworkingforone.top",
  "planetworkingforthreo.top","planetworkingfortwo.top",
  "planetworkingfouro.top","planetwrokingclassforagemt.top",
  "planetwrokinghighclassforagemt.top","planunionforharmont.top",
  "plnetcorresnifagenttea.top","qualityfilesghost.live","readyforwin.info",
  "realindeedworkingagent.top","redjohntiger.top","rizkidworikingjuice.top",
  "runtownagtabackup.top","servingbacking.top","sunbeitnetwork.com",
  "thetromalwinner.top","unrealjustcoffe.top",
  "unrelatedworkingagentcoofe.top","villanworkingforteaschop.top",
  "whiteshash.sbs","worksymansonlne.us"
]);
DeviceNetworkEvents
| where RemoteUrl has_any (AgtaDomains)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
```

## 3. Fingerprint hunt -- the version endpoint

The single strongest indicator. Every panel in this network answers this path;
the value returned (`1.7.77`, `1.7.72` or `1.7.64`) tells you which build you
are looking at. Deliberately not pinned to a version string, so it survives a
version bump as well as infrastructure rotation.

```kql
DeviceNetworkEvents
| where RemoteUrl contains "AgtaBackupAgent.version"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
```

## 4. Agta agent service persistence

```kql
DeviceEvents
| where ActionType == "ServiceInstalled"
| where AdditionalFields has "AgtaBackupAgentSvc"
   or AdditionalFields has "Agta Backup"
| project Timestamp, DeviceName, ActionType, AdditionalFields
```

## 5. Agta scheduled tasks (quick-command and self-heal)

```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("AgtaHideSC","AgtaWifiKeeper","AgtaBackupAgentHealth")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

## 6. Agta install paths and masquerading binary

```kql
DeviceFileEvents
| where FolderPath has "Agta Backup"
   or (FileName =~ "Credential Guard.exe" and FolderPath !startswith "C:\\Windows")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName
```

## 7. Broad hunt -- freshly-registered cheap-TLD egress from workstations

Not Agta-specific, but the registration pattern behind this network (bulk
cheap TLDs, word-salad names) shows up here. Expect noise; tune to your
environment before alerting.

```kql
DeviceNetworkEvents
| where RemoteUrl matches regex @"\.(top|sbs|cyou|wiki|one)($|/)"
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe")
| summarize Connections=count(), Hosts=dcount(DeviceName) by RemoteUrl, InitiatingProcessFileName
| order by Connections desc
```

## 8. ScreenConnect used to decode a script with certutil

The hands-on-keyboard step from the fake-Adobe incident: ScreenConnect's
client service runs a batch file, which uses certutil to decode a Base64 file
into a VBS and runs it.

```kql
DeviceProcessEvents
| where FileName =~ "certutil.exe" and ProcessCommandLine has "-decode"
| where InitiatingProcessParentFileName =~ "ScreenConnect.ClientService.exe"
   or ProcessCommandLine has_any (".vbs",".vbe",".js",".ps1")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

## 9. Script host launching msiexec against a URL

```kql
DeviceProcessEvents
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has "/i" and ProcessCommandLine has_any ("http://","https://")
| where InitiatingProcessFileName in~ ("cscript.exe","wscript.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```

## 10. ScreenConnect clients that aren't yours

Replace the allowlist with your own instance ID(s). The instance ID is the
hex string in the install folder name; the relay is the `h=` parameter on the
client service command line.

```kql
let MyInstances = dynamic(["<your-instance-id>"]);
DeviceProcessEvents
| where FileName =~ "ScreenConnect.ClientService.exe" or InitiatingProcessFileName =~ "ScreenConnect.ClientService.exe"
| extend Instance = extract(@"ScreenConnect Client \(([0-9a-f]{16})\)", 1, FolderPath)
| extend Relay = extract(@"[?&]h=([^&""]+)", 1, ProcessCommandLine)
| where isnotempty(Instance) and Instance !in (MyInstances)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Relays=make_set(Relay) by DeviceName, Instance
```

## 11. Fake-Adobe incident network indicators

```kql
let IncidentDomains = dynamic(["file.briefnote.pw","aprilenoxpresolve.org","planetspaceretireforthree.top"]);
DeviceNetworkEvents
| where RemoteUrl has_any (IncidentDomains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
```

## 12. Agta keylog folder permission change

The service grants the local Users group modify rights on its keylog folder so
the in-session keylogger can write to it.

```kql
DeviceProcessEvents
| where FileName =~ "icacls.exe"
| where ProcessCommandLine has "S-1-5-32-545" and ProcessCommandLine has "ProgramData"
| where InitiatingProcessFileName !in~ ("msiexec.exe","TrustedInstaller.exe")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath
```
