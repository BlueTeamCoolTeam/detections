# Disclaimer

The detection artifacts in this repository are derived from malware analysis
performed on real samples. They are provided for **defensive use only**.

## Purpose

These rules, IOCs, and queries are intended to help defenders detect malicious
activity in their environments. They are NOT intended for offensive use,
red-team engagements, or any activity that could facilitate harm.

## Test Before Deployment

- All Sigma rules carry `status: experimental` unless explicitly stated otherwise.
- Rules should be tested in a non-production environment before deployment.
- False positives are possible. Review the false-positive notes in each
  campaign README and the individual rule metadata before deploying.
- Network IOCs (domains, IPs) and file hashes may become stale as campaigns
  evolve infrastructure. Check publication dates.

## Analysis Boundaries

- Confidence levels reflect the analyst's assessment at the time of publication.
- Some campaigns include partial analysis where a component was runtime-encrypted,
  not fully executed, or not fully captured in available telemetry. These
  boundaries are explicitly documented in each campaign README and reflected
  in the `confidence` field of individual artifacts.
- Artifacts marked `confidence: research-only` have NOT been validated in a
  production environment. Do not deploy them without independent validation.

## Attribution and Accuracy

- Analysis and rules were authored by Luke Wilkinson
  ([blueteam.cool](https://blueteam.cool)). AI-assisted analysis is noted
  where applicable in the corresponding blog post.
- Errors and omissions are possible. If you identify an inaccuracy, please
  open a pull request or issue.

## No Warranty

These artifacts are provided "as is" without warranty of any kind. The author
is not responsible for any damage, data loss, missed detections, or other harm
resulting from the use or non-use of these detections.

## Contact

- Blog: https://blueteam.cool
- X: https://twitter.com/btcoolteam
- GitHub issues: https://github.com/blueteamcoolteam/detections/issues
