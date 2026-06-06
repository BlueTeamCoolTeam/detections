# blueteamcoolteam/detections

Sigma rules, YARA rules, IOCs, and detection notes from real malware analysis.
Every artifact traces back to a public write-up at
[blueteam.cool](https://blueteam.cool).

## What this is

This repository contains defensive detection artifacts derived from malware
analysis published on [blueteam.cool](https://blueteam.cool) by
[Luke Wilkinson](https://blueteam.cool/about/). Every rule, IOC list, and
query here traces back to a published analysis of a real sample.

The goal is to give defenders something concrete to take from the blog: not
just an explanation of how an attack worked, but rules and indicators they can
actually deploy or adapt.

## How it relates to blueteam.cool

Each `campaigns/` folder corresponds to a blog post. The blog explains the
analysis. This repo provides the artifacts.

Links go both ways: every campaign folder links to its source post, and the
source post links back to this folder.

## How to use these detections

**YARA**
Use with any YARA-compatible scanner (yara-python, ClamAV, EDR with YARA
support, etc.). Each rule's `meta.reference` field points to the blog post
that explains the detection logic.

```bash
yara -r campaigns/finger-lolbin-ironpython/rule.yar /path/to/scan
```

**Sigma**
Rules target Sysmon and Windows Security event logs. Use
[sigma-cli](https://github.com/SigmaHQ/sigma-cli) or
[pySigma](https://github.com/SigmaHQ/pySigma) to convert to your SIEM's
query language.

```bash
sigma convert -t splunk campaigns/finger-lolbin-ironpython/sigma-finger-exe.yml
```

All rules carry `status: experimental` unless noted otherwise. Test before
production deployment.

**IOC CSV**
Import into your threat intel platform or use for blocklist construction.
Network IOCs are defanged in prose (e.g. `example[.]com`); YARA rule
strings stay fanged so they match real content.

CSV header: `type,value,notes,confidence,post_slug`

**KQL / SPL / Devo**
Platform-specific queries are in `kql.md`, `spl.md`, and `devo.md` files
within each campaign folder where available. Marked as not production-
validated unless stated otherwise.

## Confidence levels

| Level | Meaning |
|---|---|
| `high` | Directly observed, unique artifact, near-zero false positives in normal enterprise environments. |
| `medium-high` | Strong behavioral indicator with limited but possible false positives. Validate in your environment first. |
| `medium` | Useful signal but needs environmental tuning, or derived from incomplete analysis (e.g. Pyarmor-encrypted module internals). |
| `research-only` | Not production-ready. Partial visibility, runtime-encrypted components, or unvalidated detection logic. |

## Campaigns

| Folder | Blog post | Summary | Confidence |
|---|---|---|---|
| [finger-lolbin-ironpython](campaigns/finger-lolbin-ironpython/) | [Seven layers of obfuscation, one 1970s LOLBIN](https://blueteam.cool/posts/finger-lolbin-ironpython/) | ClickFix campaign: finger.exe LOLBIN + IronPython delivering an in-process x86 shellcode beacon | High |

## Disclaimer

Detection artifacts in this repository are provided for defensive use only.
Test rules in a non-production environment before deployment. See
[DISCLAIMER.md](DISCLAIMER.md) for full terms.

## Contributing

Corrections, false-positive notes, and additional platform translations (KQL,
SPL, Devo) are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Licence

[MIT](LICENSE) -- use freely for defensive purposes. Attribution appreciated
but not required.

---

*By [Luke Wilkinson](https://blueteam.cool/about/) --
[@btcoolteam](https://twitter.com/btcoolteam)*
