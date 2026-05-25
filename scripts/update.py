#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
shai-hulud-iocs aggregator
==========================

Pulls Shai-Hulud-related compromised-package IOCs from multiple authoritative
threat-intel sources, deduplicates, normalizes, and writes a consolidated
feed to data/.

Sources (added incrementally — easy to extend):
  1. Static seed (curated by maintainer from published research)
  2. OSV.dev (Google's Open Source Vulnerabilities) — REST API, no auth required
  3. GitHub Security Advisories (GHSA) — GraphQL, uses GITHUB_TOKEN if set

Output:
  data/compromised-packages.json   (canonical, machine-readable, schema-versioned)
  data/compromised-packages.csv    (for spreadsheets)
  data/compromised-packages.txt    (one IOC per line, easy grep / curl pipe)
  data/feed.atom                   (RSS for monitoring tools)
  sources/<source>.raw.json        (per-source snapshots for debug)

Run:
  python scripts/update.py

Env:
  GITHUB_TOKEN  (optional) — raises GHSA rate limit. Auto-injected in Actions.
  DRY_RUN=1     (optional) — skip writing files (debug only)
"""

from __future__ import annotations

import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import request as urlrequest, error as urlerror
from xml.sax.saxutils import escape as xml_escape

HERE = Path(__file__).parent.parent
DATA_DIR = HERE / "data"
SOURCES_DIR = HERE / "sources"
SEED_FILE = HERE / "scripts" / "seed.json"
SCHEMA = "shai-hulud-iocs/v1"

DATA_DIR.mkdir(parents=True, exist_ok=True)
SOURCES_DIR.mkdir(parents=True, exist_ok=True)

# Force UTF-8 stdout on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

UA = "shai-hulud-iocs-aggregator/1.0 (+https://github.com/davidalmeidac/shai-hulud-iocs)"


def http_get(url: str, headers: dict | None = None, timeout: int = 30) -> bytes:
    req = urlrequest.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urlrequest.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def http_post(url: str, payload: dict, headers: dict | None = None, timeout: int = 30) -> bytes:
    body = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request(
        url,
        data=body,
        headers={
            "User-Agent": UA,
            "Content-Type": "application/json",
            **(headers or {}),
        },
        method="POST",
    )
    with urlrequest.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 1 — STATIC SEED
# ─────────────────────────────────────────────────────────────────────────────

def load_seed() -> list[dict]:
    """Curated baseline from public research (Snyk, StepSecurity, Mondoo, etc.)."""
    if not SEED_FILE.exists():
        return []
    return json.loads(SEED_FILE.read_text(encoding="utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 2 — OSV.dev
# ─────────────────────────────────────────────────────────────────────────────

# OSV uses ecosystem-specific vulnerability IDs. We query by package name
# for the seed packages and harvest any Shai-Hulud-tagged advisories.
OSV_SEARCH_QUERIES = [
    {"ecosystem": "npm", "name": "@tanstack/react-router"},
    {"ecosystem": "npm", "name": "@tanstack/router-core"},
    {"ecosystem": "npm", "name": "@opensearch-project/opensearch"},
    {"ecosystem": "npm", "name": "@mistralai/mistralai"},
    {"ecosystem": "npm", "name": "chalk-tempalte"},
]


def fetch_osv() -> list[dict]:
    """Query OSV.dev for known affected packages.

    OSV API docs: https://google.github.io/osv.dev/api/
    """
    raw_results = []
    out: list[dict] = []
    for q in OSV_SEARCH_QUERIES:
        try:
            data = http_post(
                "https://api.osv.dev/v1/query",
                {"package": {"name": q["name"], "ecosystem": q["ecosystem"]}},
                timeout=20,
            )
            parsed = json.loads(data)
            raw_results.append({"query": q, "result": parsed})
            for vuln in parsed.get("vulns", []) or []:
                # Only Shai-Hulud-tagged advisories
                summary = (vuln.get("summary") or "").lower()
                details = (vuln.get("details") or "").lower()
                if not any(kw in summary + " " + details
                           for kw in ["shai-hulud", "shai hulud", "supply-chain compromise",
                                      "supply chain compromise", "malicious code"]):
                    continue
                # Each vuln may affect multiple packages/versions
                for affected in vuln.get("affected", []) or []:
                    pkg = affected.get("package", {})
                    if pkg.get("ecosystem", "").lower() != q["ecosystem"]:
                        continue
                    versions = list(affected.get("versions") or [])
                    out.append({
                        "ecosystem": q["ecosystem"],
                        "name": pkg.get("name", q["name"]),
                        "versions": versions or ["*"],
                        "campaign": "OSV: " + (vuln.get("summary") or vuln.get("id", "unknown"))[:120],
                        "first_seen": (vuln.get("published") or "")[:10],
                        "severity": _max_severity(vuln.get("severity") or []),
                        "sources": [f"OSV: {vuln.get('id', '?')}"],
                        "references": [r.get("url") for r in (vuln.get("references") or []) if r.get("url")][:6],
                    })
            time.sleep(0.3)  # be nice to the API
        except (urlerror.URLError, urlerror.HTTPError, TimeoutError) as e:
            print(f"  [!] OSV query failed for {q['name']}: {e}", file=sys.stderr)
            continue

    (SOURCES_DIR / "osv.raw.json").write_text(
        json.dumps(raw_results, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return out


def _max_severity(severity_list: list[dict]) -> str:
    """OSV severity is a list of {type, score}. Return CVSS bucket."""
    for s in severity_list:
        score = s.get("score", "")
        if "CVSS" in s.get("type", ""):
            # Parse vector and extract base score if numeric attached
            try:
                # Some scores are full vectors (CVSS:3.1/AV:N/...) without base.
                # Just bucket loosely: "critical" if appears in summary, else high.
                pass
            except Exception:
                pass
    return "high"  # default — let humans refine in seed if needed


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE 3 — GitHub Security Advisories (GHSA)
# ─────────────────────────────────────────────────────────────────────────────

GHSA_QUERY = """
query($query: String!, $first: Int!) {
  securityAdvisories(
    first: $first,
    classifications: [GENERAL]
  ) {
    nodes {
      ghsaId
      summary
      publishedAt
      severity
      identifiers { type value }
      references { url }
      vulnerabilities(first: 50) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
        }
      }
    }
  }
}
""".strip()


def fetch_ghsa() -> list[dict]:
    """Pull GitHub Security Advisories tagged or referencing Shai-Hulud.

    Requires GITHUB_TOKEN env var. Falls back silently if missing.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("  [!] GITHUB_TOKEN not set — skipping GHSA source.", file=sys.stderr)
        (SOURCES_DIR / "ghsa.raw.json").write_text("[]", encoding="utf-8")
        return []

    out: list[dict] = []
    try:
        data = http_post(
            "https://api.github.com/graphql",
            {"query": GHSA_QUERY, "variables": {"query": "shai-hulud", "first": 100}},
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        parsed = json.loads(data)
        (SOURCES_DIR / "ghsa.raw.json").write_text(
            json.dumps(parsed, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        for adv in (parsed.get("data", {}).get("securityAdvisories", {}).get("nodes") or []):
            summary = (adv.get("summary") or "").lower()
            if "shai-hulud" not in summary and "shai hulud" not in summary:
                continue
            refs = [r.get("url") for r in (adv.get("references") or []) if r.get("url")][:6]
            for vuln in (adv.get("vulnerabilities", {}).get("nodes") or []):
                pkg = vuln.get("package") or {}
                if not pkg.get("name"):
                    continue
                out.append({
                    "ecosystem": (pkg.get("ecosystem") or "").lower(),
                    "name": pkg.get("name"),
                    "versions": [vuln.get("vulnerableVersionRange") or "*"],
                    "campaign": "GHSA: " + (adv.get("summary") or "")[:120],
                    "first_seen": (adv.get("publishedAt") or "")[:10],
                    "severity": (adv.get("severity") or "high").lower(),
                    "sources": [f"GHSA: {adv.get('ghsaId', '?')}"],
                    "references": refs,
                })
    except (urlerror.URLError, urlerror.HTTPError, TimeoutError) as e:
        print(f"  [!] GHSA query failed: {e}", file=sys.stderr)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# DEDUPE + NORMALIZE
# ─────────────────────────────────────────────────────────────────────────────

def dedupe(entries: list[dict]) -> list[dict]:
    """Merge entries that refer to the same (ecosystem, package). Union versions
    + sources + references. Keep earliest first_seen and most severe rating."""
    SEV_RANK = {"low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}

    merged: dict[tuple[str, str], dict] = {}
    for e in entries:
        key = (e.get("ecosystem", "").lower(), e.get("name", "").lower())
        if not key[0] or not key[1]:
            continue
        if key not in merged:
            merged[key] = {
                "ecosystem": e["ecosystem"],
                "name": e["name"],
                "versions": [],
                "campaigns": [],
                "first_seen": e.get("first_seen") or "",
                "severity": e.get("severity") or "high",
                "sources": [],
                "references": [],
            }
        m = merged[key]

        # Union versions
        for v in (e.get("versions") or []):
            if v and v not in m["versions"]:
                m["versions"].append(v)

        # Union campaigns
        camp = e.get("campaign")
        if camp and camp not in m["campaigns"]:
            m["campaigns"].append(camp)

        # Earliest first_seen
        if e.get("first_seen") and (not m["first_seen"] or e["first_seen"] < m["first_seen"]):
            m["first_seen"] = e["first_seen"]

        # Most severe rating
        cur = SEV_RANK.get(m["severity"], 3)
        new = SEV_RANK.get(e.get("severity", "high"), 3)
        if new > cur:
            m["severity"] = e["severity"]

        # Union sources + refs
        for s in (e.get("sources") or []):
            if s and s not in m["sources"]:
                m["sources"].append(s)
        for r in (e.get("references") or []):
            if r and r not in m["references"]:
                m["references"].append(r)

    # Final list, sorted by ecosystem then name
    return sorted(merged.values(), key=lambda x: (x["ecosystem"], x["name"].lower()))


# ─────────────────────────────────────────────────────────────────────────────
# WRITERS
# ─────────────────────────────────────────────────────────────────────────────

def write_json(packages: list[dict], generated_at: str) -> Path:
    payload = {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "total": len(packages),
        "packages": packages,
    }
    p = DATA_DIR / "compromised-packages.json"
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def write_csv(packages: list[dict]) -> Path:
    p = DATA_DIR / "compromised-packages.csv"
    with p.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ecosystem", "name", "versions", "severity", "campaigns",
                    "first_seen", "sources", "references"])
        for pkg in packages:
            w.writerow([
                pkg["ecosystem"],
                pkg["name"],
                ";".join(pkg.get("versions", [])),
                pkg.get("severity", ""),
                " | ".join(pkg.get("campaigns", [])),
                pkg.get("first_seen", ""),
                ";".join(pkg.get("sources", [])),
                ";".join(pkg.get("references", [])),
            ])
    return p


def write_txt(packages: list[dict]) -> Path:
    """One IOC per line: <ecosystem>:<name>@<version>"""
    p = DATA_DIR / "compromised-packages.txt"
    lines = []
    for pkg in packages:
        for v in pkg.get("versions", []) or ["*"]:
            lines.append(f"{pkg['ecosystem']}:{pkg['name']}@{v}")
    p.write_text("\n".join(sorted(set(lines))) + "\n", encoding="utf-8")
    return p


def write_atom(packages: list[dict], generated_at: str) -> Path:
    """Minimal RSS/Atom feed of the IOC list. Entries = most recent additions."""
    repo_url = "https://github.com/davidalmeidac/shai-hulud-iocs"
    entries = []
    for pkg in sorted(packages, key=lambda x: x.get("first_seen", ""), reverse=True)[:50]:
        versions = ", ".join(pkg.get("versions", []))
        campaigns = " · ".join(pkg.get("campaigns", []))
        sources = ", ".join(pkg.get("sources", []))
        title = xml_escape(f"{pkg['ecosystem']}:{pkg['name']} ({versions})")
        summary = xml_escape(
            f"Severity: {pkg.get('severity', 'unknown')}. "
            f"Campaigns: {campaigns or '(none)'}. "
            f"Sources: {sources or '(none)'}."
        )
        eid = xml_escape(f"{repo_url}#{pkg['ecosystem']}:{pkg['name']}")
        first_seen = pkg.get("first_seen") or generated_at[:10]
        entries.append(f"""
  <entry>
    <id>{eid}</id>
    <title>{title}</title>
    <updated>{first_seen}T00:00:00Z</updated>
    <summary>{summary}</summary>
    <link href="{repo_url}/blob/main/data/compromised-packages.json"/>
  </entry>""")

    feed = f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>shai-hulud-iocs — compromised package feed</title>
  <id>{repo_url}</id>
  <link href="{repo_url}"/>
  <updated>{generated_at}</updated>
  <author><name>davidalmeidac</name></author>
{''.join(entries)}
</feed>
"""
    p = DATA_DIR / "feed.atom"
    p.write_text(feed, encoding="utf-8")
    return p


def write_markdown(packages: list[dict], generated_at: str) -> Path:
    """Human-readable summary appended to data/SUMMARY.md."""
    by_eco: dict[str, list[dict]] = {}
    for pkg in packages:
        by_eco.setdefault(pkg["ecosystem"], []).append(pkg)

    md_lines = [
        "# Compromised packages — summary",
        "",
        f"> Generated: `{generated_at}` · Total: **{len(packages)}** unique packages",
        "",
        f"Machine-readable feed: [`compromised-packages.json`](compromised-packages.json) · ",
        f"[`compromised-packages.csv`](compromised-packages.csv) · ",
        f"[`compromised-packages.txt`](compromised-packages.txt) · ",
        f"[Atom feed](feed.atom)",
        "",
    ]

    for eco in sorted(by_eco.keys()):
        md_lines.append(f"## {eco}")
        md_lines.append("")
        md_lines.append("| Package | Versions | Severity | First seen | Sources |")
        md_lines.append("|---|---|---|---|---|")
        for pkg in sorted(by_eco[eco], key=lambda x: x["name"].lower()):
            vers = "<br>".join(f"`{v}`" for v in pkg["versions"][:5])
            srcs = ", ".join(pkg.get("sources", [])[:3])
            md_lines.append(
                f"| `{pkg['name']}` | {vers} | {pkg.get('severity', '?')} | "
                f"{pkg.get('first_seen', '?')} | {srcs} |"
            )
        md_lines.append("")

    p = DATA_DIR / "SUMMARY.md"
    p.write_text("\n".join(md_lines), encoding="utf-8")
    return p


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    print(f"[+] shai-hulud-iocs aggregator — {now_iso()}")
    all_entries: list[dict] = []

    print("[+] Loading seed...")
    seed = load_seed()
    print(f"    seed: {len(seed)} entries")
    all_entries.extend(seed)

    print("[+] Querying OSV.dev...")
    osv = fetch_osv()
    print(f"    osv: {len(osv)} entries")
    all_entries.extend(osv)

    print("[+] Querying GitHub Security Advisories...")
    ghsa = fetch_ghsa()
    print(f"    ghsa: {len(ghsa)} entries")
    all_entries.extend(ghsa)

    print(f"[+] Total raw entries: {len(all_entries)}")
    packages = dedupe(all_entries)
    print(f"[+] After dedupe: {len(packages)} unique packages")

    if os.environ.get("DRY_RUN") == "1":
        print("[!] DRY_RUN=1, skipping file writes")
        print(json.dumps(packages[:3], indent=2, ensure_ascii=False))
        return 0

    generated_at = now_iso()
    json_path = write_json(packages, generated_at)
    csv_path = write_csv(packages)
    txt_path = write_txt(packages)
    atom_path = write_atom(packages, generated_at)
    md_path = write_markdown(packages, generated_at)

    print(f"[OK] wrote {json_path}")
    print(f"[OK] wrote {csv_path}")
    print(f"[OK] wrote {txt_path}")
    print(f"[OK] wrote {atom_path}")
    print(f"[OK] wrote {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
