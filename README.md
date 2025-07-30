# vuln_finder

`vuln_finder.py` is a command-line tool that retrieves **known CVEs** and **new or unassigned vulnerabilities** for specified software and version combinations. It leverages trusted sources including **NVD** and **Vulners.com**.

---

## 🔍 Features

- Input:
  - Single software and version
  - Or a file with multiple software+version lines
- Sources:
  - [NVD](https://nvd.nist.gov) — structured CVE database
  - [Vulners](https://vulners.com) — PoCs, advisories, exploit references

---

## 📥 Requirements

- Python 3
- Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🔐 Vulners API Key (optional)

For more detailed results (e.g., PoCs, early reports):

1. Register: https://vulners.com/user/register
2. Get your API key from: https://vulners.com/userinfo/
3. Export it in your terminal:

```bash
export VULNERS_API_KEY="your_key_here"
```

If not set, Vulners results will be skipped with a warning.

---

## 🚀 Usage

### Single target:
```bash
./vuln_finder.py -s "nginx 1.18.0"
```

### Multiple targets (via file):
Example `input.txt`:
```
nginx 1.18.0
openssl 1.1.1
```

Run it:
```bash
./vuln_finder.py -f input.txt
```

---

## 📤 Output Format

```
============================================================
[+] Results for: openssl 1.1.1
============================================================

--- CVEs from NVD ---
CVE-2023-1234: Buffer overflow in ...
CVE-2022-5678: TLS handshake vuln ...

--- Other Vulnerabilities (Vulners) ---
EXPLOIT-12345: OpenSSL RCE exploit
Link: https://vulners.com/exploit-12345
```

---

## License
This tool is released under the GNU General Public License v3.0.  
Made by **k2xploit**.
