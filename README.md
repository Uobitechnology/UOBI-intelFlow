# UOBI-intelFlow
**Intelligence & OSINT Pipeline Flow** by UOBItechnology — built in Pydroid3 by Ubaid-UR-Rehman.
Open source (MIT). For research and cyber-security purposes only.

A single-file, passive OSINT / threat-intel toolkit that runs on **Pydroid3 (Android)** and any desktop Python 3.8+. It pulls **live data** from public, keyless sources and saves every result as JSON + Markdown.

> **v1.1** adds keyed enrichment, SQLite run history and STIX 2.1 export.

## Features
| Module | What you get | Sources |
|---|---|---|
| `domain` | DNS (A/AAAA/MX/NS/TXT/CAA), SPF/DMARC posture, RDAP registration, subdomains from certificate logs, archived URLs, HTTP fingerprint + security headers, robots/security.txt | Google DoH, rdap.org, crt.sh, Wayback CDX |
| `ip` | Reverse DNS, geo/ASN/hosting/proxy flags, open ports + CVEs + tags, RDAP owner, C2 / abuse blocklist hits | ip-api, Shodan InternetDB, RDAP, Feodo Tracker, Blocklist.de |
| `cve` | CVE ID or keyword search, CVSS, **actively-exploited (CISA KEV)** flag | NVD, CISA KEV |
| `feeds` | Live dashboard: newest KEV entries, C2 IP list, security news | CISA, abuse.ch, Blocklist.de, THN, BleepingComputer, Krebs |
| `search` | Web search results | DuckDuckGo |
| `dark` | Search the onion-site index (clearnet, no Tor needed) | Ahmia |
| `onion` | Fetch a `.onion` page you provide via Tor; title, text, IoCs, linked onions | Your local Tor / Orbot |
| `enrich` | VirusTotal, AlienVault OTX, AbuseIPDB, Shodan for an IP / domain / hash (your own free API keys) | VT, OTX, AbuseIPDB, Shodan |
| `history` | Every run is stored locally; list, search or reopen by id | SQLite (`uobi_history.db`) |
| `stix` | STIX 2.1 bundle of **unvetted** indicators from a report file, run id or text | local |
| `extract` | Pull IPs, domains, URLs, emails, hashes, CVEs, onion & BTC addresses from text or a file (handles `hxxp`, `[.]`) | local |

## Install (Pydroid3)
1. Pydroid3 → **Pip** → install `requests` (required). Optional: `beautifulsoup4`, `pysocks`.
2. Copy `Projectfile.py` into Pydroid3 and press **Run** → interactive menu.

Desktop: `pip install -r requirements.txt && python Projectfile.py`

## CLI
```
python Projectfile.py domain example.com
python Projectfile.py ip 1.1.1.1
python Projectfile.py cve CVE-2024-3400
python Projectfile.py cve "apache struts"
python Projectfile.py feeds
python Projectfile.py search "site:pastebin.com example.com"
python Projectfile.py dark "data leak"
python Projectfile.py onion xxxxxxxx.onion --tor
python Projectfile.py extract suspicious.txt
python Projectfile.py enrich 8.8.8.8
python Projectfile.py history            # latest 30 runs
python Projectfile.py history example    # search
python Projectfile.py history 12         # full stored result
python Projectfile.py stix 12            # STIX bundle from run 12
```
Flags: `--tor` route via Tor · `--full` print everything · `--no-save` skip report files.
Reports go to `uobi_reports/`.

## Honest limits
- "Real time" = queried live from public sources at run time; coverage is as good as those sources.
- The deep/dark web is not magically searchable. `dark` uses a public onion index that filters abusive content; `onion` only visits URLs you give it.
- Core modules need no API keys. `enrich` needs your own keys (menu 12, or env vars `VT_KEY`, `OTX_KEY`, `ABUSEIPDB_KEY`, `SHODAN_KEY`). Keys are stored in `uobi_keys.json` - never share or commit it (the included `.gitignore` excludes it).
- STIX output is a convenience export of unvetted observables (confidence 15). Review before sharing or blocking anything.
- Passive only: no scanning, no exploitation, no login attempts.

## Legal & ethics
Use only on assets you own, are authorised to assess, or for public-interest research. Do not use it to harass, stalk, or profile private individuals. Respect each source's terms and rate limits. You are responsible for how you use it.

## Contributing
Fork → add a function returning a `dict` → register it in `run()` and `menu()` → PR. Keep it Pydroid3-friendly (pure-Python dependencies).
