#!/usr/bin/env python3
"""
UOBI-intelFlow | INTELLIGENCE And OSINT Pipeline Flow
Brand : UOBItechnology
Built in Pydroid3 by "Ubaid-UR-Rehman"
Built for research and cyber-security purposes only. License: MIT (open source)

Passive OSINT / threat-intel toolkit. Only public, keyless sources.
Needs: requests (required), beautifulsoup4 + PySocks (optional).
v1.1: keyed enrichment, SQLite history, STIX 2.1 export.
Usage:  python Projectfile.py            -> interactive menu (best for Pydroid3)
        python Projectfile.py domain example.com
        python Projectfile.py -h
"""
import argparse, concurrent.futures as cf, datetime, ipaddress, json, os
import re, socket, sqlite3, sys, uuid, xml.etree.ElementTree as ET
from urllib.parse import parse_qs, urlparse

try:
    import requests
except ImportError:
    sys.exit("Install first:  pip install requests")
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

VERSION = "1.1"
def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


UA = f"UOBI-intelFlow/{VERSION} (research; passive OSINT)"
OUT_DIR = "uobi_reports"
SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy",
               "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]
URLS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "blocklistde": "https://lists.blocklist.de/lists/all.txt",
}
RSS = {
    "TheHackerNews": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "CISA-Alerts": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "KrebsOnSecurity": "https://krebsonsecurity.com/feed/",
}


# ───────────────────────── network helpers ─────────────────────────
def redact(t):
    return re.sub(r"(?i)(key|apikey|token)=[^&\s'\"]+", r"\1=***", str(t))[:200]


class Net:
    tor = False
    proxy = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}

    @classmethod
    def get(cls, url, **kw):
        kw.setdefault("timeout", 20)
        h = kw.pop("headers", {})
        h.setdefault("User-Agent", UA)
        if cls.tor:
            kw["proxies"] = cls.proxy
        return requests.get(url, headers=h, **kw)


def jget(url, **kw):
    try:
        r = Net.get(url, **kw)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": redact(e)}


_cache = {}


def listset(url):
    if url not in _cache:
        try:
            t = Net.get(url, timeout=40).text
            _cache[url] = {l.strip() for l in t.splitlines() if l.strip() and not l.startswith("#")}
        except Exception:
            _cache[url] = set()
    return _cache[url]


def page_text(html):
    if BeautifulSoup:
        s = BeautifulSoup(html, "html.parser")
        for t in s(["script", "style"]):
            t.decompose()
        return re.sub(r"\s+", " ", s.get_text(" ")).strip()
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def page_title(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else None


# ───────────────────────── IoC extraction ─────────────────────────
IOC = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "url": r"https?://[^\s\"'<>)\]]+",
    "email": r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b",
    "domain": r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "cve": r"\bCVE-\d{4}-\d{4,}\b",
    "onion": r"\b[a-z2-7]{16,56}\.onion\b",
    "btc": r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
}
BAD_EXT = (".py", ".js", ".png", ".jpg", ".gif", ".css", ".txt", ".md", ".html", ".json", ".svg")


def refang(t):
    return (t.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
             .replace("hxxp", "http").replace("[at]", "@"))


def extract(text):
    text = refang(text)
    out = {}
    for k, rx in IOC.items():
        found = set(re.findall(rx, text, re.I if k in ("domain", "onion", "cve") else 0))
        if k == "domain":
            found = {d.lower() for d in found if not d.lower().endswith(BAD_EXT)}
        if k == "cve":
            found = {c.upper() for c in found}
        if found:
            out[k] = sorted(found)
    return out


# ───────────────────────── domain module ─────────────────────────
def doh(name, rtype):
    j = jget("https://dns.google/resolve", params={"name": name, "type": rtype})
    return [a["data"] for a in j.get("Answer", [])]


def dns_all(d):
    r = {t: doh(d, t) for t in ("A", "AAAA", "MX", "NS", "TXT", "CAA")}
    dm = doh("_dmarc." + d, "TXT")
    spf = [t for t in r["TXT"] if "v=spf1" in t]
    r["email_posture"] = {"spf": spf or "MISSING", "dmarc": dm or "MISSING"}
    return {k: v for k, v in r.items() if v}


def rdap_domain(d):
    j = jget(f"https://rdap.org/domain/{d}")
    if "error" in j:
        return j
    reg = None
    for e in j.get("entities", []):
        if "registrar" in e.get("roles", []):
            for it in (e.get("vcardArray") or [None, []])[1]:
                if it[0] == "fn":
                    reg = it[3]
    return {"status": j.get("status"), "registrar": reg,
            "events": {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])},
            "nameservers": [n.get("ldhName") for n in j.get("nameservers", [])]}


def crtsh(d):
    j = jget("https://crt.sh/", params={"q": f"%.{d}", "output": "json"}, timeout=45)
    if isinstance(j, dict):
        return j
    names = set()
    for row in j:
        for n in row.get("name_value", "").split("\n"):
            names.add(n.strip().lstrip("*.").lower())
    return sorted(names)


def wayback(d):
    j = jget("https://web.archive.org/cdx/search/cdx", timeout=45,
             params={"url": d + "/*", "output": "json", "fl": "original",
                     "collapse": "urlkey", "limit": 60})
    if isinstance(j, dict):
        return j
    return [r[0] for r in j[1:]]


def http_info(d):
    for scheme in ("https", "http"):
        try:
            r = Net.get(f"{scheme}://{d}", timeout=12)
            h = r.headers
            return {"final_url": r.url, "status": r.status_code, "title": page_title(r.text),
                    "server": h.get("Server"), "x_powered_by": h.get("X-Powered-By"),
                    "security_headers": {k: (k in h) for k in SEC_HEADERS},
                    "redirects": [x.url for x in r.history]}
        except Exception as e:
            err = str(e)[:150]
    return {"error": err}


def well_known(d):
    out = {}
    for p in ("robots.txt", ".well-known/security.txt"):
        try:
            r = Net.get(f"https://{d}/{p}", timeout=10)
            if r.status_code == 200 and "<html" not in r.text[:300].lower():
                out[p] = r.text.splitlines()[:25]
        except Exception:
            pass
    return out


def domain(d):
    d = d.lower().strip().replace("http://", "").replace("https://", "").split("/")[0]
    jobs = {"dns": dns_all, "rdap": rdap_domain, "subdomains_crtsh": crtsh,
            "wayback_urls": wayback, "http": http_info, "well_known": well_known}
    res = {"target": d}
    with cf.ThreadPoolExecutor(6) as ex:
        fut = {k: ex.submit(f, d) for k, f in jobs.items()}
        for k, f in fut.items():
            try:
                res[k] = f.result()
            except Exception as e:
                res[k] = {"error": str(e)[:150]}
    return res


# ───────────────────────── IP module ─────────────────────────
def ip_lookup(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return {"error": "invalid IP"}
    if a.is_private or a.is_loopback or a.is_reserved:
        return {"error": "private/reserved IP - nothing public to look up"}
    res = {"target": ip}
    try:
        res["reverse_dns"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        res["reverse_dns"] = None
    g = jget(f"http://ip-api.com/json/{ip}",
             params={"fields": "status,country,regionName,city,isp,org,as,asname,hosting,proxy,mobile"})
    res["geo_asn"] = g
    res["shodan_internetdb"] = jget(f"https://internetdb.shodan.io/{ip}")
    r = jget(f"https://rdap.org/ip/{ip}")
    res["rdap"] = r if "error" in r else {k: r.get(k) for k in
                  ("name", "handle", "country", "startAddress", "endAddress", "type")}
    res["in_feodo_c2_list"] = ip in listset(URLS["feodo"])
    res["in_blocklist_de"] = ip in listset(URLS["blocklistde"])
    return res


# ───────────────────────── CVE module ─────────────────────────
def kev_items():
    return jget(URLS["kev"], timeout=40).get("vulnerabilities", [])


def cve(q):
    p = {"cveId": q.upper()} if re.fullmatch(r"(?i)cve-\d{4}-\d{4,}", q) \
        else {"keywordSearch": q, "resultsPerPage": 10}
    j = jget(URLS["nvd"], params=p, timeout=45)
    if "error" in j:
        return j
    kev = {v["cveID"] for v in kev_items()}
    out = []
    for v in j.get("vulnerabilities", []):
        c = v["cve"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        score = None
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            if c.get("metrics", {}).get(key):
                score = c["metrics"][key][0]["cvssData"].get("baseScore")
                break
        out.append({"id": c["id"], "published": c.get("published"), "cvss": score,
                    "actively_exploited_CISA_KEV": c["id"] in kev,
                    "description": desc[:400],
                    "refs": [r["url"] for r in c.get("references", [])[:4]]})
    return {"query": q, "results": out}


# ───────────────────────── live feeds ─────────────────────────
def rss(name, url):
    try:
        r = Net.get(url, timeout=20)
        root = ET.fromstring(r.content)
        items = []
        for it in list(root.iter("item"))[:6]:
            items.append({"title": (it.findtext("title") or "").strip(),
                          "link": (it.findtext("link") or "").strip(),
                          "date": it.findtext("pubDate")})
        return items
    except Exception as e:
        return {"error": str(e)[:120]}


def feeds():
    res = {}
    kev = sorted(kev_items(), key=lambda x: x.get("dateAdded", ""), reverse=True)[:10]
    res["cisa_kev_latest"] = [{"cve": k["cveID"], "added": k["dateAdded"],
                               "product": f'{k["vendorProject"]} {k["product"]}',
                               "ransomware_use": k.get("knownRansomwareCampaignUse")} for k in kev]
    f = listset(URLS["feodo"])
    res["feodo_c2_ips"] = {"count": len(f), "sample": sorted(f)[:10]}
    res["blocklist_de_count"] = len(listset(URLS["blocklistde"]))
    with cf.ThreadPoolExecutor(4) as ex:
        news = {n: ex.submit(rss, n, u) for n, u in RSS.items()}
        res["news"] = {n: f.result() for n, f in news.items()}
    res["fetched_at_utc"] = now_utc().isoformat(timespec="seconds")
    return res


# ───────────────────────── web / deep-web ─────────────────────────
def search(q):
    try:
        r = requests.post(
            "https://html.duckduckgo.com/html/", data={"q": q}, headers={"User-Agent": UA},
            timeout=20, proxies=Net.proxy if Net.tor else None)
    except Exception as e:
        return {"error": str(e)[:150]}
    out = []
    if BeautifulSoup:
        for a in BeautifulSoup(r.text, "html.parser").select("a.result__a")[:15]:
            href = a.get("href", "")
            real = parse_qs(urlparse(href).query).get("uddg", [href])[0]
            out.append({"title": a.get_text(strip=True), "url": real})
    else:
        out = [{"url": u} for u in sorted(set(re.findall(r"uddg=([^&\"]+)", r.text)))[:15]]
    return {"query": q, "results": out}


def dark(q):
    """Search onion-site index via Ahmia (clearnet, no Tor needed)."""
    try:
        r = Net.get("https://ahmia.fi/search/", params={"q": q}, timeout=30)
    except Exception as e:
        return {"error": str(e)[:150]}
    out = []
    if BeautifulSoup:
        for li in BeautifulSoup(r.text, "html.parser").select("li.result")[:20]:
            a = li.find("a")
            m = re.search(IOC["onion"], (a.get("href", "") if a else "") + li.get_text(" "))
            out.append({"title": a.get_text(strip=True) if a else None,
                        "onion": m.group(0) if m else None,
                        "snippet": (li.find("p").get_text(strip=True)[:200] if li.find("p") else None)})
    else:
        out = [{"onion": o} for o in sorted(set(re.findall(IOC["onion"], r.text)))[:20]]
    return {"query": q, "note": "Ahmia filters abusive content. Open results only via Tor.",
            "results": out}


def onion(url):
    """Fetch an .onion page through local Tor SOCKS (Orbot / tor on 127.0.0.1:9050)."""
    Net.tor = True
    chk = jget("https://check.torproject.org/api/ip", timeout=40)
    if not chk.get("IsTor"):
        return {"error": "Tor not routing. Start Orbot (SOCKS 9050) and run: pip install pysocks",
                "detail": chk}
    if not url.startswith("http"):
        url = "http://" + url
    try:
        r = Net.get(url, timeout=90)
    except Exception as e:
        return {"error": str(e)[:200]}
    txt = page_text(r.text)
    return {"url": url, "status": r.status_code, "title": page_title(r.text),
            "text_snippet": txt[:800], "iocs": extract(r.text),
            "linked_onions": sorted(set(re.findall(IOC["onion"], r.text)))[:50]}


def extract_cmd(arg):
    if os.path.isfile(arg):
        with open(arg, errors="ignore") as f:
            arg = f.read()
    return extract(arg)


# ───────────────────────── keyed enrichment ─────────────────────────
KEYS_FILE = "uobi_keys.json"
KEY_NAMES = ["VT_KEY", "OTX_KEY", "ABUSEIPDB_KEY", "SHODAN_KEY"]


def load_keys():
    try:
        with open(KEYS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def get_key(name):
    return os.environ.get(name) or load_keys().get(name)


def set_key(name, value):
    k = load_keys()
    k[name] = value
    with open(KEYS_FILE, "w") as f:
        json.dump(k, f)
    try:
        os.chmod(KEYS_FILE, 0o600)
    except Exception:
        pass


def kind_of(t):
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", t):
        return "hash"
    return "domain"


def _vt(t, k, key):
    path = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}[k]
    j = jget(f"https://www.virustotal.com/api/v3/{path}/{t}", headers={"x-apikey": key})
    if "error" in j:
        return j
    a = j.get("data", {}).get("attributes", {})
    return {"analysis_stats": a.get("last_analysis_stats"), "reputation": a.get("reputation"),
            "tags": a.get("tags"), "name": a.get("meaningful_name"),
            "categories": a.get("categories")}


def _otx(t, k, key):
    if k == "ip":
        typ = "IPv6" if ":" in t else "IPv4"
    else:
        typ = {"domain": "domain", "hash": "file"}[k]
    j = jget(f"https://otx.alienvault.com/api/v1/indicators/{typ}/{t}/general",
             headers={"X-OTX-API-KEY": key})
    if "error" in j:
        return j
    pulses = j.get("pulse_info", {})
    return {"pulse_count": pulses.get("count"),
            "pulses": [p.get("name") for p in pulses.get("pulses", [])[:8]],
            "reputation": j.get("reputation"), "country": j.get("country_name")}


def _abuse(t, k, key):
    j = jget("https://api.abuseipdb.com/api/v2/check", headers={"Key": key, "Accept": "application/json"},
             params={"ipAddress": t, "maxAgeInDays": 90})
    if "error" in j:
        return j
    d = j.get("data", {})
    return {f: d.get(f) for f in ("abuseConfidenceScore", "totalReports", "countryCode",
                                  "isp", "usageType", "isTor", "lastReportedAt")}


def _shodan(t, k, key):
    j = jget(f"https://api.shodan.io/shodan/host/{t}", params={"key": key})
    if "error" in j:
        return j
    return {f: j.get(f) for f in ("org", "os", "ports", "vulns", "hostnames", "last_update")}


def enrich(t):
    t = refang(t.strip())
    k = kind_of(t)
    res = {"target": t, "type": k}
    srcs = [("virustotal", "VT_KEY", _vt, ("ip", "domain", "hash")),
            ("alienvault_otx", "OTX_KEY", _otx, ("ip", "domain", "hash")),
            ("abuseipdb", "ABUSEIPDB_KEY", _abuse, ("ip",)),
            ("shodan", "SHODAN_KEY", _shodan, ("ip",))]
    for name, kn, fn, kinds in srcs:
        if k not in kinds:
            continue
        key = get_key(kn)
        if not key:
            res[name] = f"no key - set {kn} (menu 12 or env var)"
            continue
        try:
            res[name] = fn(t, k, key)
        except Exception as e:
            res[name] = {"error": redact(e)}
    return res


# ───────────────────────── SQLite history ─────────────────────────
DB = "uobi_history.db"


def db():
    c = sqlite3.connect(DB)
    c.execute("create table if not exists runs(id integer primary key autoincrement, "
              "ts text, kind text, target text, result text)")
    return c


def db_log(kind, target, res):
    try:
        c = db()
        c.execute("insert into runs(ts,kind,target,result) values(?,?,?,?)",
                  (now_utc().isoformat(timespec="seconds"), kind, target, json.dumps(res, default=str)))
        c.commit()
        c.close()
    except Exception as e:
        print("[!] history not saved:", e)


def history_cmd(q=""):
    c = db()
    try:
        if q.isdigit():
            row = c.execute("select ts,kind,target,result from runs where id=?", (int(q),)).fetchone()
            if not row:
                return {"error": "no such run id"}
            return {"id": int(q), "ts": row[0], "kind": row[1], "target": row[2], "result": json.loads(row[3])}
        like = f"%{q}%"
        rows = c.execute("select id,ts,kind,target from runs where target like ? or kind like ? "
                         "order by id desc limit 30", (like, like)).fetchall()
        return {"runs": [{"id": r[0], "ts": r[1], "kind": r[2], "target": r[3]} for r in rows],
                "tip": "history <id> shows the full stored result"}
    finally:
        c.close()


# ───────────────────────── STIX 2.1 export ─────────────────────────
STIX_SKIP = {"rdap.org", "crt.sh", "dns.google", "web.archive.org", "ip-api.com",
             "internetdb.shodan.io", "check.torproject.org"}


def _sid(t):
    return f"{t}--{uuid.uuid4()}"


def _esc(v):
    return v.replace("\\", "\\\\").replace("'", "\\'")


def stix(arg):
    """Build a STIX 2.1 bundle of UNVETTED indicators from a report .json, a history run id, or text."""
    if os.path.isfile(arg):
        with open(arg, errors="ignore") as f:
            text = f.read()
    elif arg.isdigit():
        text = json.dumps(history_cmd(arg))
    else:
        text = arg
    iocs = extract(text)
    ts = now_utc().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ident = {"type": "identity", "spec_version": "2.1", "id": _sid("identity"), "created": ts,
             "modified": ts, "name": "UOBI-intelFlow", "identity_class": "system"}
    pats = []
    for ip in iocs.get("ipv4", []):
        try:
            a = ipaddress.ip_address(ip)
            if not (a.is_private or a.is_loopback or a.is_reserved):
                pats.append(("ipv4", ip, f"[ipv4-addr:value = '{_esc(ip)}']"))
        except ValueError:
            pass
    for d in iocs.get("domain", []):
        if d not in STIX_SKIP:
            pats.append(("domain", d, f"[domain-name:value = '{_esc(d)}']"))
    for u in iocs.get("url", []):
        pats.append(("url", u, f"[url:value = '{_esc(u)}']"))
    for e in iocs.get("email", []):
        pats.append(("email", e, f"[email-addr:value = '{_esc(e)}']"))
    for k, algo in (("md5", "MD5"), ("sha1", "SHA-1"), ("sha256", "SHA-256")):
        for h in iocs.get(k, []):
            pats.append((k, h, f"[file:hashes.'{algo}' = '{h.lower()}']"))
    objs = [ident]
    for kind, val, pat in pats[:500]:
        objs.append({"type": "indicator", "spec_version": "2.1", "id": _sid("indicator"),
                     "created": ts, "modified": ts, "created_by_ref": ident["id"],
                     "name": f"{kind}: {val}"[:200], "pattern": pat, "pattern_type": "stix",
                     "valid_from": ts, "indicator_types": ["unknown"], "confidence": 15,
                     "description": "Unvetted observable extracted from an OSINT lookup. "
                                    "Verify before sharing or blocking."})
    return {"type": "bundle", "id": _sid("bundle"), "objects": objs}


# ───────────────────────── output ─────────────────────────
def to_md(o, lvl=0):
    pad = "  " * lvl
    if isinstance(o, dict):
        s = ""
        for k, v in o.items():
            if isinstance(v, (dict, list)):
                s += f"{pad}- **{k}**:\n{to_md(v, lvl + 1)}"
            else:
                s += f"{pad}- **{k}**: {v}\n"
        return s
    if isinstance(o, list):
        return "".join(f"{pad}- {x}\n" if not isinstance(x, (dict, list))
                       else f"{pad}-\n{to_md(x, lvl + 1)}" for x in o)
    return f"{pad}{o}\n"


def save(kind, target, res):
    os.makedirs(OUT_DIR, exist_ok=True)
    stamp = now_utc().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(OUT_DIR, f"{kind}_{re.sub(r'[^A-Za-z0-9.-]', '_', target)[:40]}_{stamp}")
    with open(base + ".json", "w") as f:
        json.dump(res, f, indent=2, default=str)
    with open(base + ".md", "w") as f:
        f.write(f"# UOBI-intelFlow report: {kind} / {target}\n_UTC {stamp}_\n\n{to_md(res)}")
    return base


def show(res, full=False):
    if not isinstance(res, dict):
        print(json.dumps(res, indent=2)[:3000])
        return
    for k, v in res.items():
        s = json.dumps(v, indent=2, default=str)
        print(f"\n== {k} ==")
        print(s if full or len(s) < 700 else s[:700] + f"\n... (+{len(s) - 700} chars, see saved report)")


def run(kind, arg, full=False, nosave=False):
    fn = {"domain": domain, "ip": ip_lookup, "cve": cve, "feeds": lambda _: feeds(),
          "dark": dark, "onion": onion, "extract": extract_cmd, "search": search,
          "enrich": enrich, "history": history_cmd, "stix": stix}[kind]
    print(f"[*] {kind}: {arg or ''} ...")
    res = fn(arg)
    show(res, full)
    if kind != "history":
        db_log(kind, arg or "live", res)
        if not nosave:
            print("\n[+] saved:", save(kind, arg or "live", res) + ".json / .md")
    return res


BANNER = f"""
 _   _  ___  ____ ___        _       _       _ _____ _
| | | |/ _ \\| __ )_ _|      (_)_ __ | |_ ___| |  ___| | _____      __
| | | | | | |  _ \\| |_____  | | '_ \\| __/ _ \\ | |_  | |/ _ \\ \\ /\\ / /
| |_| | |_| | |_) | |_____| | | | | | ||  __/ |  _| | | (_) \\ V  V /
 \\___/ \\___/|____/___|      |_|_| |_|\\__\\___|_|_|   |_|\\___/ \\_/\\_/
 UOBI-intelFlow v{VERSION} | UOBItechnology | MIT | research use only
"""


def menu():
    print(BANNER)
    opts = {"1": ("domain", "Domain recon"), "2": ("ip", "IP intel"),
            "3": ("cve", "CVE / keyword"), "4": ("feeds", "Live threat feeds"),
            "5": ("search", "Web search"), "6": ("dark", "Dark-web index search (Ahmia)"),
            "7": ("onion", "Fetch .onion page (needs Tor)"),
            "8": ("extract", "Extract IoCs (text or file path)"),
            "9": ("enrich", "Keyed enrichment (VT/OTX/AbuseIPDB/Shodan)"),
            "10": ("history", "Run history (blank = latest, or id / keyword)"),
            "11": ("stix", "STIX 2.1 export (report path / run id / text)"),
            "12": ("setkey", "Set API key")}
    while True:
        for k, (_, label) in opts.items():
            print(f" {k}) {label}")
        print(" 0) Exit")
        c = input("\nChoose> ").strip()
        if c == "0":
            return
        if c not in opts:
            continue
        kind = opts[c][0]
        if kind == "setkey":
            print(", ".join(f"{n} ({'set' if get_key(n) else 'empty'})" for n in KEY_NAMES))
            n = input("Key name> ").strip().upper()
            if n in KEY_NAMES:
                set_key(n, input("Value> ").strip())
                print("[+] saved to", KEYS_FILE, "(keep this file private)\n")
            continue
        blank_ok = kind in ("feeds", "history")
        arg = "" if kind == "feeds" else input("Input> ").strip()
        if blank_ok or arg:
            run(kind, arg)
        print()


def main():
    ap = argparse.ArgumentParser(description="UOBI-intelFlow passive OSINT toolkit")
    ap.add_argument("kind", nargs="?", choices=["domain", "ip", "cve", "feeds", "dark",
                                                "onion", "extract", "search", "enrich",
                                                "history", "stix", "menu"])
    ap.add_argument("target", nargs="?", default="")
    ap.add_argument("--tor", action="store_true", help="route all requests via Tor SOCKS 9050")
    ap.add_argument("--full", action="store_true", help="print full output")
    ap.add_argument("--no-save", action="store_true")
    a = ap.parse_args()
    Net.tor = a.tor
    if not a.kind or a.kind == "menu":
        return menu()
    if a.kind not in ("feeds", "history") and not a.target:
        ap.error("target required")
    run(a.kind, a.target, a.full, a.no_save)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] stopped")
