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

def enrich_domain(domain_raw: str, max_pages: int = 25, timeout: int = 45,
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
        "spf_configured": "No",
        "dmarc_configured": "No",
        "latest_snapshot_year": "",
        "cms": "Custom / Unknown",
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
        "ssl_valid": "No"
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

        # Start Scanner
        scanner = SpiderFootScanner(
            scanName=scan_name,
            scanId=scan_id,
            targetValue=domain,
            targetType="INTERNET_NAME",
            moduleList=module_list,
            globalOpts=sf_config,
            start=True
        )

        # start=True runs the scan inline in the constructor (it blocks via
        # waitForThreads), so by here the scan is already done. `status` is a
        # property, not getStatus(). maxpages is the real runtime bound, not `timeout`.
        _ = scanner.status

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

                # No module emits PAGE_TITLE; pull it from the (truncated but
                # <head>-first) stored homepage HTML instead.
                if evt_type == "TARGET_WEB_CONTENT" and not record["page_title"]:
                    tm = re.search(r"<title[^>]*>([^<]+)</title>", data, re.IGNORECASE)
                    if tm:
                        record["page_title"] = tm.group(1).strip()[:100]

                elif evt_type == "PROVIDER_MAIL":
                    record["mail_provider"] = data

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

                elif evt_type == "EMAILADDR":
                    em = data.lower()
                    # Scope to the target domain — dnsresolve/sslcert/accounts pull in
                    # affiliate/co-hosted domains we don't want in the lead's email list.
                    edom = em.split("@")[-1]
                    if (EMAIL_REGEX.match(em) and (edom == domain or edom.endswith("." + domain))
                            and not any(x in em for x in ["example.com", "sentry.io", "wixpress"])):
                        emails.add(em)

                elif evt_type == "PHONE_NUMBER":
                    phones.add(data)

                elif evt_type == "HUMAN_NAME":
                    if len(data.split()) in [2, 3] and not any(x in data.lower() for x in ["copyright", "privacy", "terms", "admin"]):
                        names.add(data)

                elif evt_type == "COMPANY_NAME":
                    companies.add(data)

                elif evt_type == "SOCIAL_MEDIA":
                    d_low = data.lower()
                    if "facebook.com/" in d_low and not socials.get("facebook"):
                        socials["facebook"] = data
                    elif "linkedin.com/" in d_low and not socials.get("linkedin"):
                        socials["linkedin"] = data
                    elif "instagram.com/" in d_low and not socials.get("instagram"):
                        socials["instagram"] = data

                elif evt_type in ["SSL_CERTIFICATE_ISSUER", "SSL_CERTIFICATE_EXPIRY"]:
                    record["ssl_valid"] = "Yes"

                elif evt_type == "INTERESTING_FILE_HISTORIC" or "HISTORIC" in evt_type:
                    match = re.search(r"\b(20\d{2})\b", data)
                    if match:
                        record["latest_snapshot_year"] = match.group(1)

        # DMARC — one direct lookup (_dmarc. subdomain, which no module queries)
        if _has_dmarc(domain):
            record["dmarc_configured"] = "Yes"

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

        if names:
            record["decision_makers"] = "; ".join(list(names)[:3])
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
                 timeout: int = 45, deep: bool = False) -> list[dict]:
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
    print("engine self-check OK")


if __name__ == "__main__":
    _selfcheck()
