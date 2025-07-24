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
                                "description": "Environment configuration file is publicly accessible and may contain credentials or secret keys.",
                                "summary": "Exposed `.env` files can leak database passwords, API keys, and other critical secrets.",
                                "remediation": "Restrict access to sensitive files via server configuration or `.htaccess`. Never expose `.env` files in production."
                                })

        except httpx.RequestError:
            pass
    print("[bold green]Exposed file check completed.[/bold green]\n")
    return results
# This script checks for common sensitive files that should not be publicly accessible.