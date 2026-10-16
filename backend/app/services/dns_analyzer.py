import re

import dns.exception
import dns.resolver

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}\.?$", re.I)
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


def lookup(domain: str) -> dict:
    results = {}
    for kind in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, kind, lifetime=3)
            results[kind] = [a.to_text() for a in answers]
        except dns.exception.DNSException:
            results[kind] = []
    return results
