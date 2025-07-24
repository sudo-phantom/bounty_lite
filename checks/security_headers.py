import httpx
from rich import print

HEADERS_TO_CHECK = {
    "Content-Security-Policy": {
        "desc": "Helps prevent XSS and data injection attacks.",
        "summary": "Missing CSP allows attackers to inject scripts (XSS), compromising site integrity and user data.",
        "remediation": "Add Content-Security-Policy header with a strict policy like: default-src 'self';"
    },
    "Strict-Transport-Security": {
        "desc": "Forces HTTPS and prevents SSL stripping.",
        "summary": "Without HSTS, attackers can downgrade users to HTTP and intercept traffic.",
        "remediation": "Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
    },
    "X-Frame-Options": {
        "desc": "Mitigates clickjacking attacks.",
        "summary": "Missing header lets attackers embed the site in iframes to trick users into malicious clicks.",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME type sniffing.",
        "summary": "Allows browser to guess content type, leading to XSS in some cases.",
        "remediation": "Add X-Content-Type-Options: nosniff"
    }
}

def run(domain):
    print("[bold green]Checking for security headers...[/bold green]")
    results = []
    try:
        r = httpx.get(domain, timeout=5)
        for header, meta in HEADERS_TO_CHECK.items():
            if header not in r.headers:
                print(f"[yellow][!] Missing Security Header:[/yellow] {header}")
                results.append({
                    "title": f"Missing Security Header: {header}",
                    "url": domain,
                    "description": f"{header} is missing. {meta['desc']}",
                    "summary": meta['summary'],
                    "remediation": meta['remediation']
                })
    except httpx.RequestError:
        pass
    return results
# This script checks for common security headers in HTTP responses.
# It identifies missing headers that could lead to security vulnerabilities.