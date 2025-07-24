import httpx
from rich import print

COMMON_PATHS = ["admin/", "uploads/", "backup/", "test/", "dev/"]

def run(domain):
    print("[bold green]Checking for open directories...[/bold green]")
    results = []
    for path in COMMON_PATHS:
        url = f"{domain.rstrip('/')}/{path}"
        try:
            r = httpx.get(url, timeout=5)
            if r.status_code == 200 and "Index of" in r.text:
                print(f"[yellow][!] Open Directory Found:[/yellow] {url}")
                results.append({
                    "title": "Open Directory",
                    "url": url,
                    "description": "Exposed directory listing accessible to unauthenticated users.",
                    "summary": "An open directory can expose sensitive files or backups that weren't intended to be public.",
                    "remediation": "Disable directory listing via the web server configuration (e.g., Apache: `Options -Indexes`, Nginx: `autoindex off;`).",
                    "cwe_id": "CWE-548",
                    "proof": f"Directory listing found at: {url}"
                })
        except httpx.RequestError:
            pass
    print("[bold green]Open directory check completed.[/bold green]\n")
    return results
# This script checks for common open directories on a given domain.