# netcon-wmi-etherhiding

Blog post: https://blueteam.cool/posts/netcon-wmi-etherhiding/

## Summary

"NetCon" is a JScript backdoor that persists as a WMI `ActiveScriptEventConsumer`
rather than a scheduled task, run key, or dropped file. The `__EventFilter` /
`__EventConsumer` / `__FilterToConsumerBinding` triad lives entirely in the WMI
repository; when the bound filter fires, WMI hands the script's `ScriptText`
directly to the scripting engine in-process under `scrcons.exe` -- no payload
file ever touches disk.

Once running, the script resolves its command-and-control address by calling
`eth_getStorageAt` against an Ethereum smart contract through a legitimate
public RPC provider (EtherHiding) -- the C2 hostname is never hardcoded, only
read live from blockchain storage. It then polls the resolved host, RC4-decrypts
a hex-encoded tasking response using its own bot UUID as the decryption key, and
`eval()`s the result -- a full interactive remote-code-execution channel.
Reading the operator's wallet transaction history on-chain (public and
permanent) reconstructed a 13-month, two-contract, eight-domain C2 rotation
history, including one contract that was hijacked by an anti-EtherHiding
"vigilante" bot before the operator deployed an access-controlled replacement.

```
__EventFilter --> __FilterToConsumerBinding --> __EventConsumer (ActiveScriptEventConsumer "NetCon")
                                                        |
                                          scrcons.exe runs ScriptText in-process
                                                        |
                              eth_getStorageAt (Ethereum contract, public RPC) --> C2 hostname
                                                        |
                        POST bot UUID --> /signin  |  hex-decode --> RC4-decrypt (key = UUID)  |  eval()
                                                        |
                                          POST result/error --> /clb  |  loop
```

## What is included

| File | Description |
|---|---|
| `iocs.csv` | Full indicator set: hashes, WMI consumer name, bot UUID/RC4 key, RPC method/endpoint, current + historical C2 domains and IPs, both EtherHiding contract addresses, operator wallet |
| `rule.yar` | YARA rule matching the NetCon JScript source (RC4 KSA shape, EtherHiding call, C2 URI paths, bot UUID) |
| `sigma-wmi-scriptevent-consumer-suspicious.yml` | Sigma rule for new WMI `__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding` registrations (Sysmon 19/20/21) |
| `sigma-wmi-scriptevent-payload-content.yml` | Sigma rule flagging `ActiveScriptEventConsumer` content containing `ActiveXObject`/`eval`/`ExecuteGlobal` |
| `sigma-etherhiding-rpc-from-process.yml` | Sigma rule for blockchain RPC JSON-RPC calls from a non-browser process -- general EtherHiding indicator, not specific to this sample |
| `kql.md` | Microsoft Sentinel / Defender XDR hunt queries for WMI registration events, scrcons.exe/WmiPrvSE.exe network activity, blockchain RPC calls, and this campaign's known indicators |

## Coverage notes

**What these detections cover:**
- Registration of the WMI persistence triad itself (any campaign using this
  technique, not just NetCon).
- The specific NetCon sample's source content, C2 protocol paths, and bot UUID.
- The general EtherHiding C2-resolution pattern (public RPC calls from
  unexpected processes), independent of which contract or domain is currently
  live.
- The full historical + current C2 domain/IP rotation set for this campaign.

**What they do NOT cover:**
- The actual second-stage tasking payload the C2 sends back on `/signin` --
  this was deliberately not retrieved during analysis (see the blog post's
  methodology note) and only exists transiently on the live server. Full
  decryption capability (RC4, key = bot UUID) is documented for use against
  any future PCAP capture.
- The `__EventFilter` WQL trigger condition bound to "NetCon" -- not present in
  the recovered record. Pull `__EventFilter`/`__FilterToConsumerBinding`
  directly from an affected host's WMI repository to determine the actual
  trigger.
- Future C2 domains/IPs the operator rotates to after this post's publication
  date (2026-07-10) -- the EtherHiding RPC-call Sigma rule is the durable
  detection for that; the domain/IP list in `iocs.csv` is a point-in-time
  snapshot.
- Any host-based EDR telemetry beyond what Sysmon/Defender for Endpoint expose
  for WMI activity -- adjust field names for your specific EDR schema.

## False-positive notes

- **WMI registration rules:** legitimate management/monitoring software
  (SCCM, some AV/EDR agents) creates permanent WMI subscriptions. Baseline
  known-good consumer/filter names in your environment before alerting
  broadly on Sysmon 19/20/21 alone.
- **ActiveXObject/eval content rule:** rare in legitimate scripted consumers,
  but possible in bespoke internal automation. Verify against a known-good
  baseline rather than auto-remediating on a single hit.
- **Blockchain RPC rule:** any host legitimately running a crypto wallet, dApp,
  or blockchain development tooling will trigger this. Baseline expected
  software before broad alerting; the rule is tuned to exclude the major
  browsers only.

## Confidence

High confidence on everything directly observed: the JScript source is
plaintext (no obfuscation to second-guess), and the EtherHiding resolution
chain and the full domain-rotation history were independently re-verified
against live/on-chain data during analysis. The inner tasking payload's exact
capability is unknown/unrecovered by design (see coverage notes) -- treat any
detection as a confirmed persistence + C2-resolution hit, not confirmation of
a specific secondary action, unless a PCAP capture is decrypted separately.

## Related detections

- `iocs.csv`
- `rule.yar`
- `sigma-wmi-scriptevent-consumer-suspicious.yml`
- `sigma-wmi-scriptevent-payload-content.yml`
- `sigma-etherhiding-rpc-from-process.yml`
- `kql.md`
