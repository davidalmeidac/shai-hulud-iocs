# shai-hulud-iocs

[![Update IOC feed](https://github.com/davidalmeidac/shai-hulud-iocs/actions/workflows/update.yml/badge.svg)](https://github.com/davidalmeidac/shai-hulud-iocs/actions/workflows/update.yml)
[![License: CC0-1.0](https://img.shields.io/badge/License-CC0_1.0-lightgrey.svg)](LICENSE)

> **Public, consolidated, machine-readable feed of npm/PyPI/etc packages confirmed compromised by the [Shai-Hulud worm framework](https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/) and its variants.**

Aggregated daily from OSV.dev, GitHub Security Advisories, and curated public research (Snyk, StepSecurity, Mondoo, Upwind, Datadog, TheHackerNews). Free for anyone to consume in their CI/CD, SIEM, or threat-intel pipeline.

---

## Why this exists

When **TeamPCP open-sourced the Shai-Hulud framework on May 12, 2026**, clones started landing in npm within days (TanStack, AntV, Mistral, chalk-template typosquats…). The IOC signal is spread across half a dozen feeds — Snyk's blog, StepSecurity's blog, OSV.dev, GHSA, Mondoo posts. **There was no single consolidated feed you could `curl` into your CI.**

This repo is that feed.

- 🟢 **Aggregator, not detector** — every entry is sourced from at least one published advisory, so zero false positives.
- 🟢 **Updated daily** via GitHub Actions cron.
- 🟢 **Multiple formats** — JSON, CSV, TXT, Atom.
- 🟢 **CC0 license** — public domain, no attribution required.
- 🟢 **Schema-versioned** so consumers can pin (`schema: shai-hulud-iocs/v1`).

---

## Use it

### As a curl in your CI

```bash
# Pull the txt feed and fail the build if any installed package matches
curl -fsSL https://raw.githubusercontent.com/davidalmeidac/shai-hulud-iocs/main/data/compromised-packages.txt \
  | grep -F "$(jq -r '.packages | to_entries[] | "npm:\(.key)@\(.value.version)"' package-lock.json)" \
  && { echo "Compromised package detected!"; exit 2; } \
  || echo "Clean."
```

### As a JSON dependency in your tool

```bash
curl -fsSL https://raw.githubusercontent.com/davidalmeidac/shai-hulud-iocs/main/data/compromised-packages.json -o iocs.json
```

```python
import json, urllib.request
url = "https://raw.githubusercontent.com/davidalmeidac/shai-hulud-iocs/main/data/compromised-packages.json"
data = json.loads(urllib.request.urlopen(url).read())
print(f"Tracking {data['total']} compromised packages, generated {data['generated_at']}")
```

### As an Atom feed in your monitoring tool

Add this URL to Feedly / NewsBlur / Inoreader / your SIEM:

```
https://raw.githubusercontent.com/davidalmeidac/shai-hulud-iocs/main/data/feed.atom
```

### As the IOC source for `sealed-env hunt-shai-hulud`

The [sealed-env hunt-shai-hulud](https://github.com/davidalmeidac/sealed-env) command will switch to consuming this feed in a future release, so adopters get fresh IOCs without re-installing the CLI.

---

## Files

| File | Format | Purpose |
|---|---|---|
| [`data/compromised-packages.json`](data/compromised-packages.json) | JSON schema `shai-hulud-iocs/v1` | Canonical machine-readable |
| [`data/compromised-packages.csv`](data/compromised-packages.csv) | CSV | Spreadsheets / Excel |
| [`data/compromised-packages.txt`](data/compromised-packages.txt) | `<eco>:<pkg>@<ver>` one per line | Easy grep / pipe |
| [`data/feed.atom`](data/feed.atom) | Atom | RSS readers / SIEMs |
| [`data/SUMMARY.md`](data/SUMMARY.md) | Markdown | Human-readable table |
| [`sources/*.raw.json`](sources/) | Raw per-source JSON | Audit trail / debugging |

---

## JSON schema (`shai-hulud-iocs/v1`)

```jsonc
{
  "schema": "shai-hulud-iocs/v1",
  "generated_at": "2026-05-25T20:08:25Z",
  "total": 5,
  "packages": [
    {
      "ecosystem": "npm",
      "name": "@tanstack/react-router",
      "versions": ["1.169.5", "1.169.8"],
      "campaigns": [
        "Mini Shai-Hulud TanStack",
        "OSV: GHSA-xxxx-xxxx-xxxx — supply-chain compromise..."
      ],
      "first_seen": "2026-05-11",
      "severity": "critical",
      "sources": ["Snyk", "StepSecurity", "OSV: GHSA-xxxx-xxxx-xxxx"],
      "references": [
        "https://snyk.io/blog/tanstack-npm-packages-compromised/",
        "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-..."
      ]
    }
  ]
}
```

Fields:
- **`ecosystem`** — `npm`, `pypi`, `maven`, etc.
- **`name`** — package name as it appears in its registry
- **`versions`** — array of exact version strings; `["*"]` means all versions of the package
- **`campaigns`** — human-readable list of named campaigns this IOC was associated with
- **`first_seen`** — earliest `YYYY-MM-DD` we have evidence for
- **`severity`** — `low` / `medium` / `high` / `critical`
- **`sources`** — list of source identifiers
- **`references`** — URLs to source advisories / writeups

---

## Sources aggregated

| Source | Method | Notes |
|---|---|---|
| **Seed** (curated) | `scripts/seed.json` | High-confidence IOCs from named campaigns |
| **OSV.dev** | REST API | Google's open-source vulnerability database |
| **GHSA** | GraphQL API | GitHub Security Advisories tagged Shai-Hulud |

More sources planned for `v1.1`: Snyk Vuln DB, Socket.dev, Aikido, npm advisories. PRs welcome.

---

## How to contribute a new IOC

1. Fork
2. Add to [`scripts/seed.json`](scripts/seed.json) with at least one **public source reference**
3. Run `python scripts/update.py` locally to verify
4. PR with the reference URL in the description

Bar for acceptance: **published in a public advisory** (Snyk, StepSecurity, Datadog, NVD, GHSA, Mondoo, Aikido, Socket, etc.) — no rumors, no anonymous reports.

---

## What this is NOT

- ❌ Not a malware scanner — see [sealed-env hunt-shai-hulud](https://github.com/davidalmeidac/sealed-env)
- ❌ Not a replacement for Snyk / Socket / Phylum / commercial scanners
- ❌ Not exhaustive — only what's been publicly documented
- ❌ Not real-time — daily refresh

It's a **single curl-able place** for IOCs that are already public but scattered.

---

## License

[CC0 1.0 Universal — Public Domain](LICENSE). No attribution required. Copy, fork, embed, re-publish freely.

## Related

- [`davidalmeidac/sealed-env`](https://github.com/davidalmeidac/sealed-env) — cross-stack encrypted `.env` library with `hunt-shai-hulud` CLI
- [`davidalmeidac/sealed-env-hunt-action`](https://github.com/davidalmeidac/sealed-env-hunt-action) — GitHub Action wrapper of the above
- [`threat-research/analysis/shai-hulud-defense.md`](https://github.com/davidalmeidac/sealed-env/blob/main/threat-research/analysis/shai-hulud-defense.md) — full defensive analysis
