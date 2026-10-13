import dns.resolver

def lookup(domain: str) -> dict:
    results = {}
    for kind in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = dns.resolver.resolve(domain, kind, lifetime=3)
            results[kind] = [a.to_text() for a in answers]
        except Exception:
            results[kind] = []
    return results
