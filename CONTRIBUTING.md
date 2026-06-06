# Contributing

Contributions that improve the quality and coverage of these detections are
welcome. The goal is accurate, conservative detections that practitioners can
trust -- not volume.

## What we accept

### False-positive corrections

If a rule fires on legitimate activity in your environment:

- Open a PR with a description of the false positive (what process or behaviour triggered it)
- Include a proposed fix (additional condition, exception, or field filter)
- Keep all links back to the original blog post intact

### Additional platform translations

If a campaign folder has YARA and Sigma but lacks KQL, Splunk SPL, or Devo DQL:

- Add a `kql.md`, `spl.md`, or `devo.md` file using the existing file naming conventions
- Mark any query not production-validated with: `# NOT VALIDATED IN PRODUCTION -- test before deploying`
- Include a brief explanation of what the query detects and any tuning notes

### IOC corrections

If an IOC is incorrectly defanged, contains a typo, or has a stale confidence
level, open a PR with the correction and a note explaining the source.

### Rule improvements

Additional detection strings, improved conditions, or performance improvements
are welcome, provided they do not reduce coverage for the original use case.

## What we do not accept

- Offensive tooling or payloads of any kind
- Rules that reference non-public infrastructure
- Confidence level increases without maintainer review -- only the original
  analyst can confirm analysis boundaries
- New campaign folders without a corresponding public blog post at blueteam.cool
- Rules that cannot be traced to a published analysis

## Guidelines

- Keep all links back to the original blog post intact in YARA `reference`
  fields and campaign READMEs
- Maintain existing file naming: `rule.yar`, `rule-<component>.yar`,
  `sigma-<description>.yml`, `iocs.csv`, `kql.md`, `spl.md`, `devo.md`
- For YARA: include `author`, `date`, `description`, `reference`, `sha256`,
  `severity`, and `confidence` in the `meta:` section
- For Sigma: include `title`, `id`, `status`, `description`, `references`,
  `author`, `date`, `tags`, `logsource`, `detection`, and `falsepositives`
- IOC CSV header must be: `type,value,notes,confidence,post_slug`

## Pull request process

1. Fork the repo and create a descriptively-named branch:
   `fix/<campaign>-<brief-description>` or `add/<campaign>-<platform>`
2. Make your changes
3. Verify YARA syntax if possible: `yara -s <rule.yar> <test-file>`
4. Verify Sigma YAML syntax if possible: `sigma check <file>`
5. Open a PR with a clear description of the change and why

Thank you for helping improve these detections.
