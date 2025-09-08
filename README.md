# Async Subdomain Enumeration Tool

`async_subenum.py` is a high-speed, asynchronous subdomain enumeration tool that uses **async DNS resolution** and integrates with multiple APIs for passive subdomain discovery.  
It is designed to minimize duplicate results and optionally filter subdomains based on their resolved IP addresses.

---

## 🚀 Features

- **Asynchronous DNS Resolution**  
  Uses `aiodns` with **Cloudflare DNS (1.1.1.1 & 1.0.0.1)** for fast, concurrent subdomain resolution.

- **Wordlist-Based Bruteforce**  
  Supports custom subdomain wordlists for brute-force enumeration.

- **Passive API-Based Enumeration** *(Optional)*  
  Fetches subdomains from:
  - VirusTotal API
  - SecurityTrails API
  - AlienVault OTX API

- **Duplicate Filtering** *(Default)*  
  - Filters subdomains that resolve to the same IP set (default mode).
  - Option to **disable filtering** (`-df`) to reveal virtual hosts and multiple subdomains pointing to the same IP.

- **Private/Public IP Detection**  
  Automatically labels resolved IPs as **Public** or **Private**.

- **Global Deduplication**  
  Ensures unique subdomain names across both **wordlist** and **API results**.

- **Customizable Output**  
  - Save results in **TXT** format (`-oT`)
  - Save results in **JSON** format (`-oJ`)
  - Includes subdomain → IP mapping and scan metadata.

- **Environment File Auto-Creation**  
  - Automatically creates `~/.env` with placeholders for API keys if missing.
  - API keys are loaded securely from `.env`.

---
