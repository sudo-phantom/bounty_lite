import httpx
from rich import print

def run(domain):
    print("\n[bold green]Checking for CORS misconfigurations...[/bold green]")
    results = []
    if not domain.startswith("http"):
        domain = "http://" + domain
    headers = {"Origin": "https://evil.com"}
    try:
        r = httpx.get(domain, headers=headers, timeout=5)
        acao = r.headers.get("Access-Control-Allow-Origin")
        if acao == "*" or acao == "https://evil.com":
            print(f"[magenta][!] CORS Misconfig Found:[/magenta] {domain} → ACAO: {acao}")
            results.append({
                                "title": "Cors Misconfiguration",
                                "url": acao,
                                "description": "cors misconfiguration identified."
                            })
    except httpx.RequestError:
        pass
    print("[bold green]CORS check completed.[/bold green]\n")
    return results
# This script checks for CORS misconfigurations on a given domain.