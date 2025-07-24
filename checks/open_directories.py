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
                                    "description": "Exposed directory listing accessible to unauthenticated users."
                                })

        except httpx.RequestError:
            pass
    print("[bold green]Open directory check completed.[/bold green]\n")
    return results
# This script checks for common open directories on a given domain.