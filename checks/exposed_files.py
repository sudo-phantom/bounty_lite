import httpx
from rich import print

SENSITIVE_FILES = [".env", ".git/config", ".DS_Store", ".htaccess", ".gitignore"]

def run(domain):
    print("\n[bold green]Checking for exposed files...[/bold green]")
    results = []
    if not domain.startswith("http"):
        domain = "http://" + domain
    for file in SENSITIVE_FILES:
        url = f"{domain.rstrip('/')}/{file}"
        try:
            r = httpx.get(url, timeout=5)
            if r.status_code == 200 and len(r.text.strip()) > 10:
                print(f"[red][!] Exposed File Found:[/red] {url}")
                results.append({
                    "title": "Exposed .env File",
                    "url": url,
                    "description": "...",
                    "summary": "...",
                    "remediation": "...",
                    "cwe_id": "CWE-538",
                    "proof": f"File accessible at: {url}"
                })

        except httpx.RequestError:
            pass
    print("[bold green]Exposed file check completed.[/bold green]\n")
    return results
# This script checks for common sensitive files that should not be publicly accessible.