#!/usr/bin/env python3
"""
vuln_lookup.py

Finds vulnerability information for a given JavaScript library (npm package)
and version via the OSV API (https://osv.dev/).

Usage:
  python vuln_lookup.py lodash 4.17.20
  python vuln_lookup.py react 16.13.1 --format json
  python vuln_lookup.py express 4.17.1 --ecosystem npm
"""

import argparse
import json
import sys
import urllib.request
import urllib.error

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

def query_osv(package_name: str, version: str, ecosystem: str = "npm", timeout: int = 20):
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        },
        "version": version
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OSV_QUERY_URL,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")
        raise SystemExit(f"[ERROR] OSV HTTP {e.code}: {msg}")
    except urllib.error.URLError as e:
        raise SystemExit(f"[ERROR] Failed to reach OSV: {e}")

def extract_vuln_items(osv_response: dict):
    """Return a list of dicts: {id, description, cves, references}."""
    vulns = osv_response.get("vulns") or []
    items = []
    for v in vulns:
        # Prefer 'summary', fallback to 'details'
        description = (v.get("summary") or v.get("details") or "").strip()
        # CVE IDs typically appear in 'aliases'
        aliases = v.get("aliases") or []
        cves = sorted({a for a in aliases if a.upper().startswith("CVE-")})
        # Keep a couple references (optional)
        refs = []
        for r in (v.get("references") or []):
            url = r.get("url")
            if url:
                refs.append(url)
        items.append({
            "id": v.get("id"),
            "description": description,
            "cves": cves,
            "references": refs
        })
    return items

def print_text(package: str, version: str, ecosystem: str, items: list):
    header = f"Vulnerabilities for {package}@{version} (ecosystem: {ecosystem})"
    print(header)
    print("-" * len(header))
    if not items:
        print("No known vulnerabilities found for this version on OSV.")
        return
    for idx, it in enumerate(items, 1):
        print(f"\n[{idx}] {it['id']}")
        desc = it['description'] or "(No description provided.)"
        print(f"Description:\n{desc}")
        if it["cves"]:
            print("CVEs: " + ", ".join(it["cves"]))
        else:
            print("CVEs: (None assigned yet)")
        # Optional: show up to 3 references
        if it["references"]:
            refs_to_show = it["references"][:3]
            print("References:")
            for r in refs_to_show:
                print(f"  - {r}")

def main():
    ap = argparse.ArgumentParser(description="Fetch vulnerability info (descriptions + CVEs) for an npm package version via OSV.")
    ap.add_argument("package", help="Package name (e.g., lodash)")
    ap.add_argument("version", help="Exact version (e.g., 4.17.20)")
    ap.add_argument("--ecosystem", default="npm", help="Package ecosystem (default: npm)")
    ap.add_argument("--format", choices=["text", "json"], default="text", help="Output format (default: text)")
    ap.add_argument("--timeout", type=int, default=20, help="HTTP timeout in seconds (default: 20)")
    args = ap.parse_args()

    resp = query_osv(args.package, args.version, ecosystem=args.ecosystem, timeout=args.timeout)
    items = extract_vuln_items(resp)

    if args.format == "json":
        out = {
            "package": args.package,
            "version": args.version,
            "ecosystem": args.ecosystem,
            "vulnerabilities": items
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_text(args.package, args.version, args.ecosystem, items)

if __name__ == "__main__":
    main()

