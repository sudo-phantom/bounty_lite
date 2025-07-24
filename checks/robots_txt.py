import httpx
from rich import print

def run(domain):
    print("[bold green]Checking for robots.txt entries...[/bold green]")
    results = []
    url = domain.rstrip("/") + "/robots.txt"
    try:
        r = httpx.get(url, timeout=5)
        if r.status_code == 200 and "Disallow:" in r.text:
            lines = r.text.splitlines()
            for line in lines:
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path not in ["/", ""]:
                        full_url = domain.rstrip("/") + path
                        print(f"[cyan][!] Found disallowed path:[/cyan] {full_url}")
                        results.append({
                                            "title": "robots.txt Disallowed Path",
                                            "url": full_url,
                                            "description": "robots.txt file disallows access to a potentially sensitive path.",
                                            "summary": "Sensitive directories hidden via robots.txt are still accessible and often contain admin, staging, or debug interfaces.",
                                            "remediation": "Avoid listing sensitive paths in robots.txt; use authentication and access control instead."
                                            })
    except httpx.RequestError:
        pass
    return results
# This script checks for disallowed paths in the robots.txt file of a given domain.
# It identifies paths that should not be indexed by search engines and may lead to sensitive content.