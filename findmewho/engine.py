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

# Active 20 Gold Passive Modules (100% Keyless, $0, Zero Port 25)
ACTIVE_MODULES = [
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
    'sfp_gravatar',
    'sfp_accounts',
    'sfp_archiveorg',
    'sfp__stor_db'
]

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
    return domain

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

def enrich_domain(domain_raw: str, max_pages: int = 25, timeout: int = 45) -> dict:
    """
    Enriches a single domain through findme-who's 22-module passive event graph.
    
    Args:
        domain_raw (str): Target domain or URL (e.g. "bondidental.com.au")
        max_pages (int): Max pages for sfp_spider to crawl (default 25)
        timeout (int): Scan timeout in seconds (default 45)
        
    Returns:
        dict: Normalized lead intelligence record.
    """
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
            '_modules.sfp_spider.maxpages': max_pages,
            '_modules.sfp_spider.maxlevels': 2,
            '_modules.sfp_spider.pausesec': 0,
            '_modules.sfp_spider.filtermime': ['image/', 'video/', 'audio/']
        }

        dbh = SpiderFootDb(sf_config)

        # Start Scanner
        scanner = SpiderFootScanner(
            scanName=scan_name,
            scanId=scan_id,
            targetValue=domain,
            targetType="INTERNET_NAME",
            moduleList=ACTIVE_MODULES,
            globalOpts=sf_config,
            start=True
        )

        start_time = time.time()
        while time.time() - start_time < timeout:
            status = scanner.getStatus()
            if status in ["FINISHED", "ABORTED", "ERROR-FAILED"]:
                break
            time.sleep(0.5)

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

                if evt_type == "PAGE_TITLE" and not record["page_title"]:
                    record["page_title"] = data[:100]

                elif evt_type == "PROVIDER_MAIL":
                    record["mail_provider"] = data

                elif evt_type in ["DOMAIN_REGISTRATION_DATE", "RAW_RIR_DATA"]:
                    # Look for 4-digit creation year
                    match = re.search(r"\b(19\d{2}|20\d{2})\b", data)
                    if match and not record["created_year"]:
                        yr = int(match.group(1))
                        if 1985 <= yr <= time.gmtime().tm_year:
                            record["created_year"] = str(yr)
                            record["domain_age_years"] = str(max(0, time.gmtime().tm_year - yr))

                elif evt_type == "WEB_FRAMEWORK":
                    techs.add(data)
                    record["cms"] = data

                elif evt_type in ["TRACKER_ID", "WEB_ANALYTICS_ID"]:
                    d_low = data.lower()
                    if "pixel" in d_low or "facebook" in d_low or "meta" in d_low:
                        record["has_meta_pixel"] = "Yes"
                    if "gtm" in d_low or "google tag manager" in d_low:
                        record["has_gtm"] = "Yes"
                    if "ga4" in d_low or "g-" in d_low:
                        record["has_ga4"] = "Yes"

                elif evt_type == "EMAILADDR":
                    em = data.lower()
                    if EMAIL_REGEX.match(em) and not any(x in em for x in ["example.com", "sentry.io", "wixpress"]):
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

def enrich_batch(domains: list[str], max_pages: int = 25, max_workers: int = 5, timeout: int = 45) -> list[dict]:
    """
    Enriches a batch of domains concurrently.
    
    Args:
        domains (list[str]): List of target domains or URLs
        max_pages (int): Max pages for sfp_spider to crawl per domain (default 25)
        max_workers (int): Concurrent scan workers (default 5)
        timeout (int): Timeout per domain in seconds (default 45)
        
    Returns:
        list[dict]: Enriched records for each domain.
    """
    clean_domains = list(dict.fromkeys([clean_domain_input(d) for d in domains if clean_domain_input(d)]))
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(enrich_domain, d, max_pages, timeout): d for d in clean_domains}
        for future in as_completed(future_to_domain):
            try:
                res = future.result()
                if res:
                    results.append(res)
            except Exception:
                pass

    return results
