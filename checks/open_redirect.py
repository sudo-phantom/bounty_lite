import httpx
from urllib.parse import urlencode
from rich import print

REDIRECT_PARAMS = ["next", "url", "target", "redir", "redirect"]
TEST_URL = "https://evil.com"

def run(domain):
    print("\n[bold green]Checking for open redirects...[/bold green]")
    results = []
    if not domain.startswith("http"):
        domain = "http://" + domain
    for param in REDIRECT_PARAMS:
        payload = {param: TEST_URL}
        url = f"{domain}?{urlencode(payload)}"
        try:
            r = httpx.get(url, follow_redirects=False, timeout=5)
            location = r.headers.get("Location", "")
            if TEST_URL in location:
                print(f"[blue][!] Open Redirect Detected:[/blue] {url}")
                results.append({
                                "title": "Open Redirect",
                                "url": url,
                                "description": "Unvalidated redirect parameter allows attacker to redirect users to arbitrary domains.",
                                "summary": "Open redirects can be used for phishing attacks or bypassing redirect-based filters and controls.",
                                "remediation": "Validate redirect parameters against an allowlist or use server-side routing references (not raw URLs)."
                                })
        except httpx.RequestError:
            pass
    print("[bold green]Open redirect check completed.[/bold green]\n")
    return results
# This script checks for open redirects by testing common redirect parameters.