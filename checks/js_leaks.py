import httpx
import re
from bs4 import BeautifulSoup
from rich import print

LEAK_PATTERNS = {
    "API Key": r"(api[_-]?key\s*=\s*[\"'][A-Za-z0-9\-_]{16,}[\"'])",
    "Bearer Token": r"(Bearer\s+[A-Za-z0-9\-_]{20,})",
    "AWS Key": r"(AKIA[0-9A-Z]{16})",
    "Secret": r"(secret[_-]?key\s*=\s*[\"'][A-Za-z0-9\-_]{10,}[\"'])",
    "Email": r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
}

def run(domain):
    print("[bold green]Scanning JS files for sensitive info...[/bold green]")
    results = []
    try:
        r = httpx.get(domain, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
        for js_path in scripts:
            if js_path.startswith("http"):
                js_url = js_path
            else:
                js_url = domain.rstrip("/") + "/" + js_path.lstrip("/")
            try:
                js = httpx.get(js_url, timeout=5)
                for label, pattern in LEAK_PATTERNS.items():
                    matches = re.findall(pattern, js.text)
                    if matches:
                        print(f"[red][!] {label} leak found in {js_url}[/red]")
                        results.append({
                                        "title": "Potential JS Leak: API Key",
                                        "url": js_url,
                                        "description": "JavaScript file contains patterns resembling API keys or other secrets.",
                                        "summary": "Leaked credentials in JavaScript can allow unauthorized access to APIs, cloud accounts, or internal services.",
                                        "remediation": "Never embed secrets in frontend JavaScript. Use server-side environment variables and secure key management instead."
                                        })
            except httpx.RequestError:
                pass
    except httpx.RequestError:
        pass
    return results
# This script scans JavaScript files linked in a webpage for sensitive information patterns.
# It looks for API keys, bearer tokens, AWS keys, secrets, and email addresses.