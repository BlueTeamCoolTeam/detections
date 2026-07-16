# KQL Queries -- kovraxis

Microsoft Sentinel / Microsoft Defender XDR queries for the Kovraxis PowerShell
downloader and Go browser-data stealer.

Blog post: https://blueteam.cool/posts/kovraxis/

> **Note:** These queries have not been validated in a production environment.
> Test and tune for your environment before deploying as alerts.

---

## 1. Hidden, execution-policy-bypassed PowerShell launcher (Defender XDR - DeviceProcessEvents)

Detects the downloader shape: hidden window, execution-policy bypass, an
indirect `Invoke-WebRequest` call building a URL from concatenated strings.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-w h" or ProcessCommandLine has "-windowstyle hidden"
| where ProcessCommandLine has_any ("-ep bypass", "-ExecutionPolicy Bypass")
| where ProcessCommandLine has_all ("Invoke-WebRequest", "UseBasicParsing")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 2. MOTW/SmartScreen bypass via SEE_MASK_NOZONECHECKS (Sentinel - Sysmon / EDR env capture)

This environment variable is rare enough that any hit is high-signal. Requires
telemetry that captures the process environment block (Sysmon does not by
default; some EDR agents do -- adjust the table/field name for your product).

```kql
// Adjust table/column names to your EDR's process-environment telemetry
DeviceProcessEvents
| where AdditionalFields has "SEE_MASK_NOZONECHECKS"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 3. Dropped-and-executed payload in %TEMP% (Defender XDR - DeviceProcessEvents / DeviceFileEvents)

Detects the specific drop pattern: `powershell.exe` writing then executing an
unsigned EXE named `x.exe` directly from `%TEMP%`.

```kql
DeviceFileEvents
| where FolderPath has @"\AppData\Local\Temp\" and FileName =~ "x.exe"
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 4. C2 network beacon (Defender XDR - DeviceNetworkEvents)

Hunts for connections to the confirmed C2 IPs and subdomain. Both IPs are
Cloudflare anycast -- expect shared-hosting noise on the IPs alone; the SNI
match on the subdomain is the higher-confidence signal.

```kql
DeviceNetworkEvents
| where (RemoteIP in ("104.21.88.153", "172.67.223.178") and RemoteUrl has "ambiltogel")
    or RemoteUrl has "bkv.ambiltogel.net"
| project Timestamp, DeviceName, AccountName, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 5. Dead-drop resolver lookups to Steam/Telegram (Defender XDR - DeviceNetworkEvents)

Detects the implant polling its dead-drop pages. On its own this overlaps with
legitimate browser traffic -- pair with query 6's TLS-fingerprint approach, or
with proxy-layer body inspection for the `hwid`/`build_id`/`format` multipart
fields, for a higher-confidence match.

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("steamcommunity.com/profiles/76561198674661449", "telegram.me/r7t3at")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe")
| project Timestamp, DeviceName, AccountName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 6. Non-browser access to Edge profile databases (Defender XDR - DeviceFileEvents)

Detects the browser-data theft telemetry: a non-browser process touching
Edge's `Login Data`, `Cookies`, `History`, or `Web Data` files, or writing
equivalently-named/shaped files outside a real profile directory.

```kql
DeviceFileEvents
| where FileName in~ ("Login Data", "Cookies", "History", "Web Data")
| where InitiatingProcessFileName !in~ ("msedge.exe", "MicrosoftEdgeUpdate.exe", "chrome.exe")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 7. Hidden decoy Edge launch (Defender XDR - DeviceProcessEvents)

Detects the implant force-initializing an Edge profile before theft: a hidden,
GPU-disabled Edge instance spawned by a non-Explorer parent.

```kql
DeviceProcessEvents
| where FileName =~ "msedge.exe"
| where ProcessCommandLine has_all ("--no-first-run", "--disable-gpu")
| where InitiatingProcessFileName !in~ ("explorer.exe", "msedge.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 8. Self-signed certificate spoofing a known company domain (Defender XDR - DeviceFileCertificateInfo)

Cheap, high-confidence rule regardless of which company gets spoofed: a binary
signed with a Subject CN matching a real, well-known domain while the
certificate is self-signed (not chain-verifiable).

```kql
DeviceFileCertificateInfo
| where IsTrusted == false
| where Subject has_any ("anthropic.com", "microsoft.com", "google.com")  // extend with other commonly-spoofed brands
| where Subject == Issuer  // self-signed
| project Timestamp, DeviceName, SHA256, Subject, Issuer, IsTrusted
| order by Timestamp desc
```
