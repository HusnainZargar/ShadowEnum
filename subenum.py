#!/usr/bin/env python3
"""
subenum.py
Subdomain Bruteforce using Async DNS (Cloudflare)
Filters duplicates based on IP set
V1.0.0
"""

import asyncio
import aiodns
import time
import sys
from pathlib import Path

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

async def resolve_subdomain(resolver, subdomain):
    """Check if subdomain resolves using DNS (Cloudflare)."""
    try:
        result_a = await resolver.query(subdomain, 'A')
        ips = sorted({r.host for r in result_a})
        return subdomain, ips
    except aiodns.error.DNSError:
        return None, None

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

async def main():
    if len(sys.argv) < 3:
        print(f"{YELLOW}Usage:{RESET} python {sys.argv[0]} <domain> <wordlist>")
        sys.exit(1)

    domain = sys.argv[1]
    wordlist_path = Path(sys.argv[2])
    if not wordlist_path.exists():
        print(f"{RED}[-] Wordlist not found: {wordlist_path}{RESET}")
        sys.exit(1)

    start_time = time.time()
    print(f"{YELLOW}[+] Starting async brute-force for {domain}{RESET}")

    live_subs = await brute_force_subdomains(domain, wordlist_path)

    elapsed = time.time() - start_time
    print(f"\n{GREEN}[+] Found {len(live_subs)} unique live subdomains in {elapsed:.2f} seconds{RESET}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"{RED}[-] Interrupted by user{RESET}")
