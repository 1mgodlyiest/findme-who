# findme-who

**findme-who** is a high-speed, 100% passive OSINT, domain reconnaissance, and digital footprint intelligence engine.

Designed and authored by **Manish Paneru**, `findme-who` distills advanced passive reconnaissance into a streamlined, high-performance Python library and CLI tool.

Zero paid API keys. Zero active port scans. Zero Port 25 probing. 100% passive intelligence.

---

## ⚡ Key Capabilities

| Intelligence Layer | Extracted Signals |
|---|---|
| **Domain & Registration** | Creation date, domain age, registrar details via RDAP/WHOIS, and Wayback historical redesign snapshots |
| **Mail & Security Posture** | Mail service provider detection (Google Workspace, Microsoft 365, cPanel/Self-hosted), SPF & DMARC configuration status |
| **Tech Stack & CMS** | Framework and CMS identification (WordPress, Shopify, Squarespace, Wix, Webflow, Drupal, etc.) |
| **Marketing & Analytics** | Active tracking pixels (Meta/Facebook Pixel, Google Tag Manager container, Google Analytics 4) |
| **Contact Intelligence** | Direct email extraction (DOM text, mailto attributes, Cloudflare email decoding), phone number discovery & classification (Mobile vs. Landline vs. Toll-Free) |
| **Social & Digital Footprint** | Connected social profiles (Facebook, LinkedIn, Instagram), Gravatar presence, brand identity verification |
| **Web Infrastructure** | Webserver signatures, SSL/TLS certificate validity, issuer, and expiration |

---

## 🚀 Installation

### Local Installation
Clone the repository and install in editable mode:
```bash
git clone https://github.com/1mgodlyiest/findme-who.git
cd findme-who
pip install -e .
```

### Install Directly via Git
```bash
pip install git+https://github.com/1mgodlyiest/findme-who.git
```

---

## 💻 Python Library Usage

`findme-who` provides a clean, programmatic interface for single-target analysis or large-scale batch processing:

```python
import findmewho

# 1. Single Domain Reconnaissance
domain_data = findmewho.enrich_domain("example.com", max_pages=15)
print(domain_data["primary_email"])
print(domain_data["cms"])
print(domain_data["mail_provider"])
print(domain_data["domain_age_years"])

# 2. High-Throughput Batch Processing
domains = ["example1.com", "example2.com", "example3.com"]
results = findmewho.enrich_batch(domains, max_workers=10, max_pages=20)

for res in results:
    print(f"{res['domain']}: {res['cms']} | {res['primary_email']}")
```

---

## 🖥️ Command-Line Interface (CLI)

Run `findme-who` directly from your terminal:

```bash
# Analyze a single domain
findme-who example.com

# Process a CSV list of domains with multi-threaded workers
findme-who domains.csv -o enriched_results.csv --threads 10 --pages 20
```

---

## 🛡️ Core Principles

- **100% Passive & Non-Intrusive:** Never performs active port scanning, vulnerability probing, or Port 25 SMTP connections.
- **$0 API Dependency:** Operates purely on public DNS records, RDAP, standard HTTP/HTTPS headers, and DOM parsing.
- **High Concurrency:** Built on a multi-threaded asynchronous event graph for rapid batch reconnaissance.
- **Clean Output Normalization:** Flattens complex graph events into structured dictionaries and CSV exports.

---

## 👤 Author

**Manish Paneru**  
*Project Repository:* [https://github.com/1mgodlyiest/findme-who](https://github.com/1mgodlyiest/findme-who)
