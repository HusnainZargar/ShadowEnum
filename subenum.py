#!/usr/bin/env python3
"""
Subdomain Bruteforce using Async DNS (Cloudflare)
API-based subdomain enumeration
dotenv support, creates ~/.env
Filters duplicates based on IP set
"""

import asyncio
import aiodns
import time
import sys
from pathlib import Path

# ===== NEW IMPORTS =====
import argparse
import aiohttp
import os
from dotenv import load_dotenv

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# ===== NEW: Ensure .env exists =====
ENV_PATH = Path.home() / ".env"
if not ENV_PATH.exists():
    with open(ENV_PATH, "w") as f:
        f.write("VIRUSTOTAL_API_KEY=\n")
        f.write("SECURITYTRAILS_API_KEY=\n")
        f.write("ALIENVAULT_API_KEY=\n")
    print(f"{YELLOW}[+] Created {ENV_PATH} with placeholder API keys{RESET}")

load_dotenv(ENV_PATH)

# ===== Original function =====
async def resolve_subdomain(resolver, subdomain):
    """Check if subdomain resolves using DNS (Cloudflare)."""
    try:
        result_a = await resolver.query(subdomain, 'A')
        ips = sorted({r.host for r in result_a})
        return subdomain, ips
    except aiodns.error.DNSError:
        return None, None

# ===== Original function =====
async def brute_force_subdomains(domain, wordlist_path, concurrency=200):
    """Run subdomain brute-force using async DNS resolution."""
    resolver = aiodns.DNSResolver()
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']  # Cloudflare DNS

    # Load wordlist
    words = []
    with open(wordlist_path, "r", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(f"{word}.{domain}")

    print(f"{YELLOW}[+] Loaded {len(words)} subdomain candidates{RESET}")

    live_subdomains = []
    seen_ip_sets = set()
    sem = asyncio.Semaphore(concurrency)

    async def worker(sub):
        async with sem:
            sub, ips = await resolve_subdomain(resolver, sub)
            if sub and ips:
                ip_tuple = tuple(ips)
                if ip_tuple not in seen_ip_sets:
                    seen_ip_sets.add(ip_tuple)
                    live_subdomains.append((sub, ips))
                    print(f"{GREEN}[LIVE]{RESET} {sub} -> {', '.join(ips)}")

    await asyncio.gather(*[worker(sub) for sub in words])
    return live_subdomains

# ===== NEW: API subdomain fetching =====
async def fetch_api_subdomains(domain):
    api_results = set()

    async with aiohttp.ClientSession() as session:
        # VirusTotal
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        if vt_key:
            vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {"x-apikey": vt_key}
            try:
                async with session.get(vt_url, headers=headers) as r:
                    if r.status == 200:
                        data = await r.json()
                        for item in data.get("data", []):
                            api_results.add(item.get("id"))
                        print(f"{YELLOW}[+] VirusTotal returned {len(api_results)} subdomains{RESET}")
            except Exception as e:
                print(f"{RED}[-] VirusTotal API error: {e}{RESET}")

        # SecurityTrails
        st_key = os.getenv("SECURITYTRAILS_API_KEY", "").strip()
        if st_key:
            st_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"APIKEY": st_key}
            try:
                async with session.get(st_url, headers=headers) as r:
                    if r.status == 200:
                        data = await r.json()
                        subs = data.get("subdomains", [])
                        for s in subs:
                            api_results.add(f"{s}.{domain}")
                        print(f"{YELLOW}[+] SecurityTrails returned {len(subs)} subdomains{RESET}")
            except Exception as e:
                print(f"{RED}[-] SecurityTrails API error: {e}{RESET}")

        # AlienVault OTX
        av_key = os.getenv("ALIENVAULT_API_KEY", "").strip()
        if av_key:
            av_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            headers = {"X-OTX-API-KEY": av_key}
            try:
                async with session.get(av_url, headers=headers) as r:
                    if r.status == 200:
                        data = await r.json()
                        for entry in data.get("passive_dns", []):
                            api_results.add(entry.get("hostname"))
                        print(f"{YELLOW}[+] AlienVault returned {len(data.get('passive_dns', []))} subdomains{RESET}")
            except Exception as e:
                print(f"{RED}[-] AlienVault API error: {e}{RESET}")

    return sorted(s for s in api_results if s and s.endswith(domain))

# ===== NEW: Resolve API subdomains with same logic =====
async def resolve_api_subdomains(subdomains):
    resolver = aiodns.DNSResolver()
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']

    live_subdomains = []
    seen_ip_sets = set()
    sem = asyncio.Semaphore(200)

    async def worker(sub):
        async with sem:
            sub, ips = await resolve_subdomain(resolver, sub)
            if sub and ips:
                ip_tuple = tuple(ips)
                if ip_tuple not in seen_ip_sets:
                    seen_ip_sets.add(ip_tuple)
                    live_subdomains.append((sub, ips))
                    print(f"{GREEN}[LIVE]{RESET} {sub} -> {', '.join(ips)}")

    await asyncio.gather(*[worker(sub) for sub in subdomains])
    return live_subdomains

# ===== Modified main to add argparse and --api =====
async def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist")
    parser.add_argument("--api", action="store_true", help="Use API-based enumeration")
    args = parser.parse_args()

    start_time = time.time()
    print(f"{YELLOW}[+] Starting async subdomain enumeration for {args.domain}{RESET}")

    live_subs_total = []

    if args.wordlist:
        live_subs = await brute_force_subdomains(args.domain, Path(args.wordlist))
        live_subs_total.extend(live_subs)

    if args.api:
        print(f"{YELLOW}[+] Fetching subdomains from APIs...{RESET}")
        api_subs = await fetch_api_subdomains(args.domain)
        print(f"{YELLOW}[+] Resolving API subdomains...{RESET}")
        live_api = await resolve_api_subdomains(api_subs)
        live_subs_total.extend(live_api)

    elapsed = time.time() - start_time
    print(f"\n{GREEN}[+] Found {len(live_subs_total)} unique live subdomains in {elapsed:.2f} seconds{RESET}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"{RED}[-] Interrupted by user{RESET}")
