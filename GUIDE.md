# UOBI-intelFlow — Quick Guide

## 1. First run (Pydroid3)
1. Pip → install `requests` (+ `beautifulsoup4`, `pysocks` optional).
2. Open `Projectfile.py` → ▶ Run.
3. Pick a number, type the target, read the result. Full output is saved in `uobi_reports/`.

## 2. Typical workflows
**Investigate a suspicious domain**
1. Menu 1 → `example.com`
2. Check: registration date (new = suspicious), `email_posture` (SPF/DMARC MISSING = spoofable), `subdomains_crtsh`, `security_headers`.
3. Take the A-record IPs → Menu 2 for each. Look at `shodan_internetdb` (ports/vulns) and the blocklist flags.

**Check an IP from your logs**
Menu 2 → IP. `in_feodo_c2_list: true` = known botnet C2; treat as high priority.

**Is a vulnerability being exploited?**
Menu 3 → `CVE-YYYY-NNNN`. `actively_exploited_CISA_KEV: true` = patch first.

**Daily briefing**
Menu 4 → latest exploited CVEs, C2 IPs, news headlines.

**Process a leaked/pasted report**
Save the text to a file → Menu 8 → file path. You get clean IoC lists (refangs `hxxp`, `[.]`).

## 3. Dark-web module
- `dark <keyword>` searches the Ahmia onion index from the normal internet. It shows onion addresses + snippets. It does not open them.
- To open a page: install **Orbot** (Android), start it (SOCKS on 127.0.0.1:9050), `pip install pysocks`, then Menu 7 or `onion <address> --tor`.
- Never download files or log in on unknown onion sites. Content can be illegal or malicious; Ahmia filtering is not perfect.

## 4. Reading results
| Field | Meaning |
|---|---|
| `events.registration` | Domain age |
| `subdomains_crtsh` | Hostnames seen in public TLS certificates |
| `wayback_urls` | Historical URLs (old admin pages, params) |
| `shodan_internetdb.vulns` | CVEs associated with exposed services |
| `hosting` / `proxy` | Cloud/VPN/proxy IP flags |
| `cvss` | 9.0+ critical, 7.0+ high |

## 5. Keyed enrichment (VirusTotal, OTX, AbuseIPDB, Shodan)
1. Create free accounts and copy your API keys.
2. Menu 12 -> key name (`VT_KEY`, `OTX_KEY`, `ABUSEIPDB_KEY`, `SHODAN_KEY`) -> paste value. Stored in `uobi_keys.json` (private; do not share/commit).
3. Menu 9 -> IP, domain or file hash. Sources without a key are skipped and tell you which key is missing.
4. Env vars also work and take priority over the file.

Add your own source: write `def _mysrc(t, k, key): return jget(url, headers={...})` and add a tuple to `srcs` inside `enrich()`. Put secrets in headers or `params=` so error output can redact them.

## 5b. History (SQLite)
Every run is saved in `uobi_history.db`.
- Menu 10 blank = latest 30 runs; a word searches target/type; a number opens that run in full.

## 5c. STIX 2.1 export
- Menu 11 with a report path (`uobi_reports/..json`), a history run id, or pasted text.
- Output: `uobi_reports/stix_*.json` bundle with indicators for public IPs, domains, URLs, emails and hashes.
- These are **unvetted observables** (confidence 15). A domain you merely looked up is not necessarily malicious. Remove benign entries before importing into MISP/OpenCTI or sharing.

## 6. Troubleshooting
| Problem | Fix |
|---|---|
| `error: ... timed out` for crt.sh | It is often overloaded; re-run later |
| Tor not routing | Orbot must be running; `pip install pysocks` |
| Empty `dark` results | Try broader keywords; index is limited |
| Rate-limited (429) | Wait; avoid repeated rapid runs |
| ip-api blocked | Free tier is 45 req/min over HTTP |
| No network on Pydroid3 | Check Android internet/VPN permissions |

## 7. Ideas for next versions
Scheduled feed runs, TAXII push, PDF report, ATT&CK tagging, more keyed sources.
