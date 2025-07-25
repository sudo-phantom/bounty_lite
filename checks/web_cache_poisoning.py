import httpx
import uuid
from rich import print

def run(domain):
    print("[bold green]Checking for web cache poisoning...[/bold green]")
    results = []
    test_header = "X-Unique-Header"
    unique_value = str(uuid.uuid4())
    url = domain if domain.startswith("http") else "http://" + domain

    try:
        # First, send a request with a unique header
        r1 = httpx.get(url, headers={test_header: unique_value}, timeout=10)
        # Then, send a normal request (no header)
        r2 = httpx.get(url, timeout=10)

        # Check if the unique value appears in the second response (possible cache poisoning)
        if unique_value in r2.text:
            print(f"[red][!] Potential Web Cache Poisoning Detected:[/red] {url}")
            results.append({
                "title": "Potential Web Cache Poisoning",
                "url": url,
                "description": "A unique header value sent in one request was reflected in a subsequent response, indicating possible cache poisoning.",
                "summary": "Web cache poisoning can allow attackers to inject malicious content into cached responses, affecting all users who receive the poisoned cache.",
                "remediation": "Ensure that user-controlled headers are not included in cache keys or reflected in cached responses. Use proper cache key normalization and validation.",
                "cwe_id": "CWE-1021",
                "proof": f"Unique header value '{unique_value}' sent in {test_header} was reflected in the response body."
            })
    except Exception as e:
        print(f"[yellow]Web cache poisoning check error: {e}[/yellow]")

    return results