#!/usr/bin/env python3
# -----------------------------------------------------------------------------
#  vuln_finder.py - CVE & Vulnerability lookup tool
#  Author: k2xploit
#  Website: https://github.com/k2xploit/vuln-finder
#
#  This program is intended for educational and authorized testing purposes only.
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------------

import argparse
import requests
import os
import urllib.parse

VULNERS_API = "https://vulners.com/api/v3/search/lucene/"
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")

def query_vulners(name, version):
    if not VULNERS_API_KEY:
        return None
    headers = {"Content-Type": "application/json"}
    params = {
        "query": f"{name} {version}",
        "apiKey": VULNERS_API_KEY
    }
    try:
        res = requests.get(VULNERS_API, params=params, headers=headers)
        res.raise_for_status()
        return res.json().get("data", {}).get("search", [])
    except Exception as e:
        print(f"[!] Error querying Vulners for {name} {version}: {e}")
        return []

def parse_input(file=None, single=None):
    targets = []
    if file:
        with open(file) as f:
            for line in f:
                if line.strip():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        targets.append((parts[0], parts[1]))
    elif single:
        parts = single.strip().split()
        if len(parts) >= 2:
            targets.append((parts[0], parts[1]))
    return targets

def query_nvd(name, version):
    try:
        query = f"{name} {version}"
        print("\n--- CVEs from NVD ---")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}"
        res = requests.get(url)
        res.raise_for_status()
        results = res.json().get("vulnerabilities", [])
        if results:
            for item in results:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "N/A")
                descriptions = cve.get("descriptions", [])
                desc = descriptions[0].get("value", "") if descriptions else ""
                print(f"{cve_id}: {desc}")
        else:
            print("No CVEs found.")
    except Exception as e:
        print(f"[!] Error querying NVD for {name} {version}: {e}")

def print_header(title):
    print("="*60)
    print(f"[+] {title}")
    print("="*60)

def main():
    parser = argparse.ArgumentParser(description="Query CVEs and Vulnerabilities")
    parser.add_argument("-f", "--file", help="File with software and version per line")
    parser.add_argument("-s", "--single", help="Single software and version")
    args = parser.parse_args()
    if not args.file and not args.single:
        parser.print_help()
        exit(1)

    targets = parse_input(args.file, args.single)

    for name, version in targets:
        print_header(f"Results for: {name} {version}")

        query_nvd(name, version)

        vulners_data = query_vulners(name, version)
        print("\n--- Other Vulnerabilities (Vulners) ---")
        if vulners_data is None:
            print("[!] Skipping Vulners query — API key not set. Export VULNERS_API_KEY to enable this.")
            print("No additional vulnerabilities found.")
        elif not vulners_data:
            print("[i] Vulners returned no results — this may be normal on the free tier.")
            print("No additional vulnerabilities found.")
        else:
            print(f"[i] Vulners returned {len(vulners_data)} results.")
            for item in vulners_data:
                doc_id = item.get('_id', 'N/A')
                score = item.get('_score', '?')
                source = item.get('_source', {})

                title = source.get('title')
                if not title:
                    desc = source.get('description', '').strip().replace('\n', ' ')
                    title = desc[:60] + "..." if len(desc) > 60 else desc

                print(f"{doc_id} (score: {score}): {title}")
                print(f"Link: https://vulners.com/search?query={doc_id}\n")

        print("\n")

if __name__ == "__main__":
    main()
