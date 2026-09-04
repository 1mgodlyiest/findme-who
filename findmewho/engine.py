# -*- coding: utf-8 -*-
"""
findmewho.engine
Native SpiderFoot Scanner driver & high-performance Lead Intelligence Normalizer.
"""

import os
import sys
import time
import tempfile
import re
from pathlib import Path
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# Ensure root findme-who directory is on sys.path so modules/ and spiderfoot/ resolve
FINDMEWHO_ROOT = str(Path(__file__).resolve().parent.parent)
if FINDMEWHO_ROOT not in sys.path:
    sys.path.insert(0, FINDMEWHO_ROOT)

from sflib import SpiderFoot
from sfscan import SpiderFootScanner
from spiderfoot import SpiderFootDb, SpiderFootHelpers

# Base pass — site crawl + DNS/WHOIS/SSL + on-page contact/tech extraction.
# All keyless, $0, no port 25, and no per-email/name fan-out, so it stays fast.
BASE_MODULES = [
    'sfp_spider',
    'sfp_whois',
    'sfp_dnsresolve',
    'sfp_dnsraw',
    'sfp_sslcert',
    'sfp_pageinfo',
    'sfp_webframework',
    'sfp_webanalytics',
    'sfp_webserver',
    'sfp_email',
    'sfp_emailformat',
    'sfp_phone',
    'sfp_names',
    'sfp_company',
    'sfp_social',
    'sfp__stor_db'
]
# sfp_archiveorg deliberately excluded: it calls the Wayback API once per URL,
# which fans out across every cert-SAN subdomain and dominates wall-clock
# (~12 min/domain on big brands). Site-history is marginal for lead gen —
# whois/RDAP domain-age already covers "how established". Re-add if ever needed.

# Deep pass — account hunting. Each probes dozens of external sites per email /
# name / username, so it adds minutes per domain. Opt-in via deep=True only.
DEEP_MODULES = ['sfp_accounts', 'sfp_gravatar', 'sfp_socialprofiles']

# URL_WEB_FRAMEWORK names that are real CMS/site-builders (vs. JS libs like jQuery).
CMS_FRAMEWORKS = {"Wordpress": "WordPress", "Shopify": "Shopify", "Wix": "Wix",
                  "Squarespace": "Squarespace", "Webflow": "Webflow", "Drupal": "Drupal",
                  "Joomla": "Joomla", "Magento": "Magento"}

# MX host substring -> friendly mail provider label.
_MAIL_PROVIDERS = [
    ("google", "Google Workspace"), ("googlemail", "Google Workspace"),
    ("outlook", "Microsoft 365"), ("microsoft", "Microsoft 365"),
    ("office365", "Microsoft 365"), ("protection.outlook", "Microsoft 365"),
    ("zoho", "Zoho Mail"), ("secureserver.net", "GoDaddy"),
    ("mailgun", "Mailgun"), ("sendgrid", "SendGrid"), ("pphosted", "Proofpoint"),
    ("messagelabs", "Symantec"), ("mimecast", "Mimecast"),
]


def classify_mail_provider(mx_host: str, domain: str) -> str:
    """Friendly label from an MX hostname. Self-hosted/cPanel when the MX is the
    domain itself (mail.domain / domain)."""
    h = (mx_host or "").lower().strip(".")
    if not h:
        return "Unknown"
    for needle, label in _MAIL_PROVIDERS:
        if needle in h:
            return label
    if h == domain or h.endswith("." + domain) or h.startswith("mail."):
        return "cPanel / Self-Hosted"
    return h  # unknown third-party — keep the raw host


EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
AU_PHONE_REGEX = re.compile(r"(?:\+?61\s?|0)(?:[2-478]\s?\d{4}\s?\d{4}|4\d{2}\s?\d{3}\s?\d{3}|1300\s?\d{3}\s?\d{3}|1800\s?\d{3}\s?\d{3})")
RAW_DIGITS_REGEX = re.compile(r"\D")

def clean_domain_input(url_or_domain: str) -> str:
    """Normalize input string to FQDN domain."""
    val = url_or_domain.strip().lower()
    if not val:
        return ""
    if not val.startswith("http://") and not val.startswith("https://"):
        val = "https://" + val
    parsed = urlparse(val)
    domain = parsed.netloc or parsed.path
    domain = domain.split(":")[0].split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def _has_dmarc(domain: str) -> bool:
    """True if _dmarc.<domain> publishes a DMARC TXT record.

    No SpiderFoot module queries the _dmarc. subdomain, so we do the one lookup
    directly. dnspython is already a dependency (sfp_dnsresolve uses it).
    """
    try:
        import dns.resolver
        answers = dns.resolver.resolve("_dmarc." + domain, "TXT")
        return any("v=dmarc1" in b"".join(r.strings).decode("utf-8", "ignore").lower()
                   for r in answers)
    except Exception:
        return False


def _domain_created_year(domain: str) -> str:
    """Registration year via RDAP (rdap.org), which exposes creation dates that
    restricted WHOIS (e.g. .au) hides. '' if unavailable."""
    try:
        import requests
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=8,
                         headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return ""
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                m = re.match(r"(\d{4})", ev.get("eventDate", ""))
                if m:
                    return m.group(1)
    except Exception:
        pass
    return ""


def _check_ssl(domain: str) -> str:
    """'Yes' if domain:443 serves a valid, in-date cert; 'No' if the cert is
    present but invalid/expired; '' if HTTPS couldn't be reached. Done directly
    (stdlib) because sfp_sslcert emits nothing reliably in this environment."""
    import socket
    import ssl
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                ss.getpeercert()  # raises on expiry / hostname mismatch
        return "Yes"
    except ssl.SSLError:
        return "No"
    except Exception:
        return ""


# COMPANY_NAME values that are domain registrars/registries (from WHOIS), not
# the actual business — skip them.
_COMPANY_NOISE = ("identity digital", "domain administration", "registry",
                  "registrar", "auda", "godaddy", "namecheap", "cloudflare",
                  "whois", "redacted", "privacy", "tucows", "domains", "dynadot")


def _company_relates_to_domain(company: str, domain: str) -> bool:
    """Keep a COMPANY_NAME only if it plausibly belongs to THIS business, not a
    registrar. sfp_company emits registrar names from WHOIS (Dynadot, Identity
    Digital, ...) which never share a word with the domain. Accept when the
    domain's core label overlaps the company text either way."""
    c = re.sub(r"[^a-z0-9]", "", company.lower())
    if not c or any(n in company.lower() for n in _COMPANY_NOISE):
        return False
    core = domain.split(".")[0]
    if core in c or c in core:
        return True
    # any 4+ char company word appearing in the domain core
    return any(w in core for w in re.findall(r"[a-z]{4,}", company.lower()))


# --- Decision-maker extraction ---------------------------------------------
# sfp_names scrapes country/region dropdowns and emits them as HUMAN_NAME
# ("Sint Maarten", "American Samoa"). Filter those, and prioritise names that
# appear next to a decision-maker title (Dr / Director / Owner / Founder / ...).
_COUNTRIES = frozenset("""afghanistan albania algeria andorra angola argentina armenia
australia austria azerbaijan bahamas bahrain bangladesh barbados belarus belgium belize
benin bermuda bhutan bolivia botswana brazil brunei bulgaria burundi cambodia cameroon
canada chad chile china colombia comoros congo croatia cuba cyprus denmark djibouti
dominica ecuador egypt eritrea estonia ethiopia fiji finland france gabon gambia georgia
germany ghana greece greenland grenada guam guatemala guinea guyana haiti honduras hungary
iceland india indonesia iran iraq ireland israel italy jamaica japan jordan kazakhstan kenya
kiribati kosovo kuwait laos latvia lebanon lesotho liberia libya lithuania luxembourg
madagascar malawi malaysia maldives mali malta mauritania mauritius mexico moldova monaco
mongolia montenegro morocco mozambique myanmar namibia nauru nepal netherlands nicaragua
niger nigeria niue norway oman pakistan palau panama paraguay peru philippines poland
portugal qatar romania russia rwanda samoa senegal serbia seychelles singapore slovakia
slovenia somalia spain sudan suriname sweden switzerland syria taiwan tajikistan tanzania
thailand togo tonga tunisia turkey turkmenistan tuvalu uganda ukraine uruguay uzbekistan
vanuatu venezuela vietnam yemen zambia zimbabwe""".split())
_PLACE_PHRASES = ("american samoa", "sint maarten", "tristan cunha", "norfolk island",
    "cook islands", "cayman islands", "faroe islands", "marshall islands", "solomon islands",
    "new zealand", "new caledonia", "south africa", "south korea", "north korea", "sri lanka",
    "saudi arabia", "united states", "united kingdom", "hong kong", "costa rica", "puerto rico",
    "el salvador", "san marino", "cape verde", "ivory coast", "papua new guinea",
    "united arab emirates", "dominican republic", "czech republic", "burkina faso",
    "sierra leone", "new south wales")
# City / place words — reject any "name" containing one (kills "Invisalign Sydney").
_CITIES = frozenset("""sydney melbourne brisbane perth adelaide canberra hobart darwin
newcastle wollongong geelong townsville cairns toowoomba ballarat bendigo launceston
london dublin auckland bondi parramatta chatswood manly""".split())
# Legal-entity suffixes ("Accreditations Pty") and web-font family words
# ("Helvetica Neue") that sfp_names emits as capitalised bigrams. Font list kept
# to words that aren't plausible personal names (no "georgia"/"times").
_COMPANY_SUFFIX = frozenset("pty ltd inc llc plc gmbh corp group holdings".split())
_FONTS = frozenset("helvetica verdana roboto tahoma calibri garamond futura "
                   "montserrat arial segoe emoji".split())

_TITLE_RE = re.compile(
    r"\b(Dr|Doctor|Prof|Professor|Director|Owner|Founder|Principal|Partner|Proprietor|CEO)\.?\s+"
    r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})")


def _is_person_name(name: str) -> bool:
    """A plausible 2-3 word personal name, not a place or dropdown junk."""
    n = name.strip()
    low = n.lower()
    words = n.split()
    if len(words) not in (2, 3):
        return False
    if low in _PLACE_PHRASES or any(w.lower() in (_COUNTRIES | _CITIES) for w in words):
        return False
    if any(w.lower() in (_COMPANY_SUFFIX | _FONTS) for w in words):
        return False
    if any(x in low for x in ("copyright", "privacy", "terms", "admin", "select", "choose")):
        return False
    return all(w[:1].isupper() and w[1:].islower() for w in words if len(w) > 1)


def format_and_classify_phone(raw_phone: str) -> tuple[str, str]:
    """Classify Australian phone into Mobile (SMS-Ready) vs Landline."""
    digits = RAW_DIGITS_REGEX.sub("", raw_phone)
    if digits.startswith("61"):
        digits = "0" + digits[2:]
    
    phone_type = "unknown"
    formatted = raw_phone.strip()

    if len(digits) == 10:
        if digits.startswith("04"):
            phone_type = "mobile"
            formatted = f"{digits[:4]} {digits[4:7]} {digits[7:]}"
        elif digits.startswith(("02", "03", "07", "08")):
            phone_type = "landline"
            formatted = f"({digits[:2]}) {digits[2:6]} {digits[6:]}"
    elif len(digits) in [10, 6] and digits.startswith(("1300", "1800", "13")):
        phone_type = "tollfree"
        formatted = raw_phone.strip()

    return formatted, phone_type

def enrich_domain(domain_raw: str, max_pages: int = 25, timeout: int = 90,
                  deep: bool = False) -> dict:
    """
    Enriches a single domain through findme-who's passive event graph.

    Args:
        domain_raw (str): Target domain or URL (e.g. "bondidental.com.au")
        max_pages (int): Max pages for sfp_spider to crawl (default 25)
        timeout (int): Scan timeout in seconds (default 45)
        deep (bool): Add the account-hunting modules (DEEP_MODULES). Slow —
            dozens of external probes per email/name. Default False (fast pass).

    Returns:
        dict: Normalized lead intelligence record.
    """
    module_list = BASE_MODULES + DEEP_MODULES if deep else list(BASE_MODULES)
    domain = clean_domain_input(domain_raw)
    if not domain:
        return {}

    import uuid
    scan_id = uuid.uuid4().hex[:16]
    scan_name = f"findmewho_{domain}_{int(time.time())}"

    # Use a unique temporary SQLite db to isolate concurrent scans
    temp_db_fd, temp_db_path = tempfile.mkstemp(prefix=f"fmw_{scan_id}_", suffix=".db")
    os.close(temp_db_fd)

    record = {
        "domain": domain,
        "page_title": "",
        "created_year": "",
        "domain_age_years": "",
        "mail_provider": "Unknown",
        "mail_host": "",
        "spf_configured": "No",
        "dmarc_configured": "No",
        "cms": "Custom / Unknown",
        "web_server": "",
        "has_meta_pixel": "No",
        "has_gtm": "No",
        "has_ga4": "No",
        "primary_email": "",
        "all_emails": "",
        "phone": "",
        "phone_type": "None",
        "mobile_phone": "",
        "landline_phone": "",
        "decision_makers": "",
        "company_name": "",
        "facebook": "",
        "linkedin": "",
        "instagram": "",
        "ssl_valid": ""
    }

    try:
        # Load module metadata dict
        mod_dir = os.path.join(FINDMEWHO_ROOT, "modules")
        sf_modules = SpiderFootHelpers.loadModulesAsDict(mod_dir, ['sfp_template.py'])

        # Cap the spider on its OWN opts dict — the scanner reads self.opts['maxpages'],
        # NOT a global '_modules.sfp_spider.*' key, so overriding here is what actually applies.
        if 'sfp_spider' in sf_modules:
            sf_modules['sfp_spider']['opts'].update({
                'maxpages': max_pages, 'maxlevels': 2, 'pausesec': 0,
                'filtermime': ['image/', 'video/', 'audio/'],
                'nosubs': True,  # stay on the exact host — no staging/subdomains
            })

        # Base SpiderFoot options
        sf_config = {
            '_debug': False,
            '_maxthreads': 5,
            '__logging': False,
            '__outputfilter': None,
            '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '_dnsserver': '',
            '_fetchtimeout': 5,
            '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
            '_internettlds_cache': 72,
            '_genericusers': "admin,support,info,sales,contact,billing,help,office,reception,enquiries",
            '__database': temp_db_path,
            '__modules__': sf_modules,
            '__correlationrules__': [],
            '__globaloptdescs__': {},
            '_socks1type': '',
            '_socks2addr': '',
            '_socks3port': '',
            '_socks4user': '',
            '_socks5pwd': '',
        }

        dbh = SpiderFootDb(sf_config)

        # SpiderFootScanner(start=True) runs the whole scan INLINE in __init__
        # (it blocks in waitForThreads), so a slow/dead domain would run
        # unbounded and, across a batch, pile up threads. Run it in a daemon
        # thread and enforce `timeout`: if it overruns, flip the scan status to
        # ABORT-REQUESTED so every module's checkForStop() bails on its next
        # cycle, then read whatever events already landed.
        def _run_scan():
            try:
                SpiderFootScanner(
                    scanName=scan_name, scanId=scan_id, targetValue=domain,
                    targetType="INTERNET_NAME", moduleList=module_list,
                    globalOpts=sf_config, start=True,
                )
            except Exception:
                pass  # abort surfaces here as AssertionError; results still stored

        import threading
        scan_thread = threading.Thread(target=_run_scan, daemon=True)
        scan_thread.start()
        scan_thread.join(timeout)
        if scan_thread.is_alive():
            try:
                dbh.scanInstanceSet(scan_id, status="ABORT-REQUESTED")
            except Exception:
                pass
            scan_thread.join(10)  # grace for modules to wind down (bounded by _fetchtimeout)

        # Harvest emitted events from DB
        import sqlite3
        conn = sqlite3.connect(temp_db_path)
        cur = conn.cursor()
        cur.execute("SELECT data, type, module FROM tbl_scan_results WHERE scan_instance_id = ?", (scan_id,))
        events = cur.fetchall()
        conn.close()

        emails = set()
        phones = set()
        names = set()
        titled = []  # names found next to a decision-maker title (higher priority)
        companies = set()
        socials = {}
        techs = set()

        if events:
            for ev in events:
                data = str(ev[0]).strip() if ev[0] else ""
                evt_type = str(ev[1]) if ev[1] else ""
                mod = str(ev[2]) if ev[2] else ""

                if not data:
                    continue

                # No module emits PAGE_TITLE; pull it from the stored homepage
                # HTML, and harvest titled decision-maker names from page text.
                if evt_type == "TARGET_WEB_CONTENT":
                    if not record["page_title"]:
                        tm = re.search(r"<title[^>]*>([^<]+)</title>", data, re.IGNORECASE)
                        if tm:
                            record["page_title"] = tm.group(1).strip()[:100]
                    for title_word, nm in _TITLE_RE.findall(data):
                        label = nm if title_word.lower() in ("director", "owner",
                            "founder", "principal", "partner", "proprietor", "ceo") \
                            else f"Dr {nm}"
                        if _is_person_name(nm) and label not in titled:
                            titled.append(label)

                elif evt_type == "PROVIDER_MAIL":
                    record["mail_host"] = data
                    record["mail_provider"] = classify_mail_provider(data, domain)

                elif evt_type == "DNS_SPF":
                    record["spf_configured"] = "Yes"

                elif evt_type == "RAW_RIR_DATA":
                    # Look for 4-digit creation year (whois has no dedicated date event here)
                    match = re.search(r"\b(19\d{2}|20\d{2})\b", data)
                    if match and not record["created_year"]:
                        yr = int(match.group(1))
                        if 1985 <= yr <= time.gmtime().tm_year:
                            record["created_year"] = str(yr)
                            record["domain_age_years"] = str(max(0, time.gmtime().tm_year - yr))

                elif evt_type == "URL_WEB_FRAMEWORK":
                    techs.add(data)
                    if data in CMS_FRAMEWORKS:
                        record["cms"] = CMS_FRAMEWORKS[data]  # real CMS; JS libs stay out

                elif evt_type == "WEB_ANALYTICS_ID":
                    # Payloads like "Google Tag Manager: GTM-x", "Google Analytics 4: G-x",
                    # "Meta Pixel: <id>". (See sfp_webanalytics for the full set.)
                    d_low = data.lower()
                    if "tag manager" in d_low:
                        record["has_gtm"] = "Yes"
                    if "google analytics" in d_low:
                        record["has_ga4"] = "Yes"
                    if "meta pixel" in d_low:
                        record["has_meta_pixel"] = "Yes"

                elif evt_type in ("EMAILADDR", "EMAILADDR_GENERIC"):
                    # GENERIC = info@/sales@/contact@ etc. — the cold-outreach
                    # addresses, emitted as a separate type; capture both.
                    em = data.lower()
                    # Scope to the target domain — dnsresolve/sslcert/accounts pull in
                    # affiliate/co-hosted domains we don't want in the lead's email list.
                    edom = em.split("@")[-1]
                    if (EMAIL_REGEX.match(em) and (edom == domain or edom.endswith("." + domain))
                            and not any(x in em for x in ["example.com", "sentry.io", "wixpress"])):
                        emails.add(em)

                elif evt_type in ("WEBSERVER_BANNER", "WEBSERVER_TECHNOLOGY"):
                    if not record["web_server"]:
                        record["web_server"] = data[:80]

                elif evt_type == "PHONE_NUMBER":
                    phones.add(data)

                elif evt_type == "HUMAN_NAME":
                    if _is_person_name(data):
                        names.add(data)

                elif evt_type == "COMPANY_NAME":
                    if _company_relates_to_domain(data, domain):
                        companies.add(data)

                elif evt_type == "SOCIAL_MEDIA":
                    # data looks like "Facebook: <SFURL>https://...</SFURL>" — pull the URL
                    m = re.search(r"https?://[^\s<>\"]+", data)
                    url = m.group(0) if m else ""
                    d_low = url.lower()
                    if "facebook.com/" in d_low and not socials.get("facebook"):
                        socials["facebook"] = url
                    elif "linkedin.com/" in d_low and not socials.get("linkedin"):
                        socials["linkedin"] = url
                    elif "instagram.com/" in d_low and not socials.get("instagram"):
                        socials["instagram"] = url

                elif evt_type == "SSL_CERTIFICATE_ISSUED":
                    if record["ssl_valid"] != "No":     # don't upgrade an expired verdict
                        record["ssl_valid"] = "Yes"     # a cert was retrieved and parsed
                elif evt_type == "SSL_CERTIFICATE_EXPIRED":
                    record["ssl_valid"] = "No"          # present but expired — wins regardless of order

        # DMARC — one direct lookup (_dmarc. subdomain, which no module queries)
        if _has_dmarc(domain):
            record["dmarc_configured"] = "Yes"

        # SSL — direct check (sfp_sslcert is unreliable); overrides any module value
        ssl_status = _check_ssl(domain)
        if ssl_status:
            record["ssl_valid"] = ssl_status

        # Domain age — RDAP fallback when WHOIS didn't yield a creation year
        if not record["created_year"]:
            yr = _domain_created_year(domain)
            if yr:
                record["created_year"] = yr
                record["domain_age_years"] = str(max(0, time.gmtime().tm_year - int(yr)))

        # Fallback / Normalize Emails
        if emails:
            email_list = list(emails)
            direct_emails = [e for e in email_list if not e.startswith(("info@", "admin@", "support@", "reception@", "contact@", "enquiries@"))]
            record["primary_email"] = direct_emails[0] if direct_emails else email_list[0]
            record["all_emails"] = "; ".join(email_list[:5])

        # Normalize Phones
        mobiles = []
        landlines = []
        tollfrees = []
        for p in phones:
            formatted, p_type = format_and_classify_phone(p)
            if p_type == "mobile" and formatted not in mobiles:
                mobiles.append(formatted)
            elif p_type == "landline" and formatted not in landlines:
                landlines.append(formatted)
            elif p_type == "tollfree" and formatted not in tollfrees:
                tollfrees.append(formatted)

        if mobiles:
            record["mobile_phone"] = mobiles[0]
            record["phone"] = mobiles[0]
            record["phone_type"] = "Mobile (SMS-Ready)"
        elif landlines:
            record["landline_phone"] = landlines[0]
            record["phone"] = landlines[0]
            record["phone_type"] = "Landline"
        elif tollfrees:
            record["phone"] = tollfrees[0]
            record["phone_type"] = "Toll-Free"

        # Titled names first (Dr/Director/Owner…), then plain names, deduped.
        seen_dm, dm = set(), []
        for n in titled + [x for x in names if x not in {t.replace("Dr ", "") for t in titled}]:
            base = n.replace("Dr ", "")
            if base not in seen_dm:
                seen_dm.add(base)
                dm.append(n)
        if dm:
            record["decision_makers"] = "; ".join(dm[:3])
        if companies:
            record["company_name"] = list(companies)[0]

        record["facebook"] = socials.get("facebook", "")
        record["linkedin"] = socials.get("linkedin", "")
        record["instagram"] = socials.get("instagram", "")

    finally:
        # Clean up temporary database
        try:
            if os.path.exists(temp_db_path):
                os.remove(temp_db_path)
        except Exception:
            pass

    return record

def enrich_batch(domains: list[str], max_pages: int = 25, max_workers: int = 5,
                 timeout: int = 90, deep: bool = False) -> list[dict]:
    """
    Enriches a batch of domains concurrently.

    Args:
        domains (list[str]): List of target domains or URLs
        max_pages (int): Max pages for sfp_spider to crawl per domain (default 25)
        max_workers (int): Concurrent scan workers (default 5)
        timeout (int): Timeout per domain in seconds (default 45)
        deep (bool): Run the slow account-hunting pass per domain (default False)

    Returns:
        list[dict]: Enriched records for each domain.
    """
    clean_domains = list(dict.fromkeys([clean_domain_input(d) for d in domains if clean_domain_input(d)]))
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(enrich_domain, d, max_pages, timeout, deep): d for d in clean_domains}
        for future in as_completed(future_to_domain):
            try:
                res = future.result()
                if res:
                    results.append(res)
            except Exception:
                pass

    return results


def _selfcheck() -> None:
    """Offline check of the deterministic parsers (the scan needs network)."""
    assert clean_domain_input("https://www.Bondidental.com.au/contact") == "bondidental.com.au"
    assert clean_domain_input("EXAMPLE.COM") == "example.com"
    assert format_and_classify_phone("0412 345 678")[1] == "mobile"
    assert format_and_classify_phone("+61 2 8197 4002")[1] == "landline"
    assert format_and_classify_phone("(07) 2480 9414")[1] == "landline"
    assert format_and_classify_phone("garbage")[1] == "unknown"
    assert EMAIL_REGEX.match("info@bondidental.com.au")
    # CMS whitelist maps builder names, drops JS libs
    assert CMS_FRAMEWORKS.get("Shopify") == "Shopify"
    assert "jQuery" not in CMS_FRAMEWORKS and "Bootstrap" not in CMS_FRAMEWORKS
    # Deep modules are opt-in only — never in the fast base pass
    assert not (set(DEEP_MODULES) & set(BASE_MODULES))
    assert "sfp_accounts" in DEEP_MODULES and "sfp_accounts" not in BASE_MODULES
    # Mail provider classification
    assert classify_mail_provider("aspmx.l.google.com", "x.com") == "Google Workspace"
    assert classify_mail_provider("x.com-mail.protection.outlook.com", "x.com") == "Microsoft 365"
    assert classify_mail_provider("mail.x.com", "x.com") == "cPanel / Self-Hosted"
    assert classify_mail_provider("", "x.com") == "Unknown"
    # Company name must relate to the domain — registrars are rejected
    assert _company_relates_to_domain("Bondi Dental Pty Ltd", "bondidental.com.au")
    assert not _company_relates_to_domain("DYNADOT LLC", "bondidental.com.au")
    assert not _company_relates_to_domain("Identity Digital Australia", "bondidental.com.au")
    # Decision-maker filter: real names in, dropdown/country junk out
    assert _is_person_name("Jane Smith") and _is_person_name("Mark Van Damme")
    assert not _is_person_name("Sint Maarten")
    assert not _is_person_name("American Samoa")
    assert not _is_person_name("New South Wales")
    assert not _is_person_name("Select Country")
    assert not _is_person_name("Invisalign Sydney")  # city word
    assert not _is_person_name("Helvetica Neue")     # web font
    assert not _is_person_name("Segoe Emoji")        # Segoe UI Emoji font
    assert not _is_person_name("Accreditations Pty")  # company suffix
    assert _is_person_name("Sarah Jones")            # real name, not blocked by font list
    assert _TITLE_RE.findall("Dr Jane Smith and Director Bob Lee") == \
        [("Dr", "Jane Smith"), ("Director", "Bob Lee")]
    print("engine self-check OK")


if __name__ == "__main__":
    _selfcheck()
