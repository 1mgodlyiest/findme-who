# findme-who

**findme-who** is a high-speed, 100% passive B2B lead enrichment engine built for Australian business intelligence.

Zero API keys. Zero Port 25. Zero cost.

It deep-crawls business websites and passively pulls contact data, tech stack signals, and digital maturity indicators across a batch of domains in seconds.

---

## What It Extracts

| Signal | Detail |
|---|---|
| **Primary Email** | Mailto links, Cloudflare-obfuscated emails, on-page text |
| **All Emails** | Full list including subpage crawl results |
| **Mobile Phone** | Australian `04XX` numbers — SMS-ready |
| **Landline Phone** | `(02)/(03)/(07)/(08)` formatted numbers |
| **Phone Type** | `Mobile (SMS-Ready)` / `Landline` / `Toll-Free` |
| **CMS / Stack** | WordPress, Wix, Squarespace, Shopify, Webflow, Drupal |
| **Meta Pixel** | Active Facebook ad spend detection |
| **Google Tag Manager** | GTM container detection |
| **Mail Provider** | Google Workspace, Microsoft 365, cPanel / Self-Hosted |
| **DMARC / SPF** | Email spoofing vulnerability check |
| **Domain Age** | Creation year and years since registration (via RDAP) |
| **Wayback Snapshot** | Last Wayback Machine archive year |
| **SSL Status** | Valid / Expired + days remaining |
| **Facebook** | Linked business page URL |
| **LinkedIn** | Linked company or personal page URL |
| **Instagram** | Linked business profile URL |
| **Mobile Responsive** | Viewport meta tag detection |

---

## How It Works

findme-who uses a **4-layer passive contact extraction waterfall**:

```
[1] Schema.org JSON-LD  ──► Official Google SEO structured data (telephone, email)
[2] Cloudflare Decoder  ──► Decodes data-cfemail="" obfuscated emails
[3] Mailto / Tel Links  ──► Direct href="mailto:" and href="tel:" extraction
[4] Multi-Page Crawl    ──► Auto-visits /contact, /about, /team, /staff
```

All phone numbers are classified:
- `04XX XXX XXX` → **Mobile (SMS-Ready)**
- `(02) XXXX XXXX` → **Landline**
- `1300 / 1800` → **Toll-Free**

---

## Usage

```bash
# Enrich a single domain
python enrich.py bondidental.com.au

# Enrich a CSV of domains
python enrich.py sydney_leads.csv -o sydney_enriched.csv

# Adjust thread count (default 15)
python enrich.py sydney_leads.csv -o sydney_enriched.csv --threads 20
```

Your CSV input just needs a column containing domain names or URLs — findme-who auto-detects them.

---

## Output

Enriched records are exported as a structured CSV with one row per domain:

```
domain, page_title, created_year, domain_age_years, mail_provider,
dmarc_configured, spf_configured, latest_snapshot_year, cms,
has_meta_pixel, has_gtm, primary_email, all_emails,
phone, phone_type, mobile_phone, landline_phone,
mobile_responsive, ssl_valid, facebook, linkedin, instagram
```

---

## Install

```bash
pip install requests dnspython beautifulsoup4 rich
```

---

## Design Rules

- **Zero API keys** — all data pulled from public DNS, RDAP, Wayback Machine, and live HTML
- **No Port 25** — never probes SMTP; uses passive MX/DMARC/SPF DNS-only checks
- **No dark web, no threat intel, no port scanning** — pure B2B lead signals only
- **Multi-threaded** — homepage + up to 3 subpages per domain crawled in parallel
- **Ponytail** — minimal code, stdlib-first, zero bloat
