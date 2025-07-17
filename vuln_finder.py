#!/usr/bin/env python3
# -----------------------------------------------------------------------------
#  vuln_finder.py - CVE & Vulnerability lookup tool
#  Copyright (C) 2025  k2xploit
#  Official github repo: https://github.com/k2xploit/vuln-finder
#
#  This tool is intended for educational and authorized testing purposes only.
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

OSV_API = "https://api.osv.dev/v1/query"
VULNERS_API = "https://vulners.com/api/v3/search/lucene/"
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")  # Optional: export before use

def query_osv(name, version):
    data = {"version": version, "package": {"name": name}}
    try:
        res = requests.post(OSV_API, json=data)
        res.raise_for_status()
        vulns = res.json().get("vulns", [])
        return vulns
    except Exception as e:
        print(f"[!] Error querying OSV for {name} {version}: {e}")
        return []

def query_vulners(name, version):
    if not VULNERS_API_KEY:
        print("[!] Skipping Vulners query — API key not set. Export VULNERS_API_KEY to enable this.")
        return []
    if not VULNERS_API_KEY:
        return []
    headers = {"Content-Type": "application/json"}
    params = {
        "query": f"{name} {version}",
        "apiKey": VULNERS_API_KEY
    }
    try:
        res = requests.get(VULNERS_API, params=params, headers=headers)
        res.raise_for_status()
        return res.json().get("data", {}).get("documents", [])
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
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
        res = requests.get(url)
        res.raise_for_status()
        results = res.json().get("vulnerabilities", [])
        if results:
            for item in results:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "N/A")
                desc = cve.get("descriptions", [{}])[0].get("value", "")
                print(f"{cve_id}: {desc}")
        else:
            print("No CVEs found.")
    except Exception as e:
        print(f"[!] Error querying NVD for {name} {version}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Query CVEs and Vulnerabilities")
    parser.add_argument("-f", "--file", help="File with software and version per line")
    parser.add_argument("-s", "--single", help="Single software and version")
    args = parser.parse_args()

    targets = parse_input(args.file, args.single)

    for name, version in targets:
        print("="*60)
        print(f"[+] Results for: {name} {version}")
        print("="*60)

        osv_vulns = query_osv(name, version)
        query_nvd(name, version)
        print("\n--- CVEs from OSV ---")
        if osv_vulns:
            for vuln in osv_vulns:
                print(f"{vuln['id']}: {vuln.get('summary', '')}")
        else:
            print("No CVEs found.")

        vulners_data = query_vulners(name, version)
        print("\n--- Other Vulnerabilities (Vulners) ---")
        if vulners_data:
            for item in vulners_data:
                print(f"{item.get('id', 'N/A')}: {item.get('title', '')}")
                print(f"Link: {item.get('href', '')}\n")
        else:
            print("No additional vulnerabilities found.")
        print("\n")

if __name__ == "__main__":
    main()
