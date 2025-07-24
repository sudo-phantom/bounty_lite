import requests
from rich import print

def get_subdomains(domain):
    print(f"[bold green]Fetching subdomains for {domain}...[/bold green]")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        subs = set(entry["name_value"] for entry in data)
        cleaned = set(s for s in subs if domain in s and "*" not in s)
        return list(cleaned)
    except Exception as e:
        print(f"[red]Error fetching subdomains: {e}[/red]")
        return []
