import typer
from checks import open_directories, web_cache_poisoning, exposed_files, cors, jwt_token, open_redirect, security_headers, robots_txt, js_leaks
from utils import report, subdomains
from rich import print
from datetime import datetime

app = typer.Typer(help="Bounty-Lite: Low-hanging fruit bug bounty recon tool.")

@app.command()
def scan(domain: str, include_subs: bool = True, wordlist: str = typer.Option(None, help="Path to wordlist for JWT secret brute-force")):
    # Split domain on newlines and strip whitespace
    domains = [d.strip() for d in domain.splitlines() if d.strip()]

    all_targets = []
    for d in domains:
        if not d.startswith("http"):
            d = "https://" + d
        base_domain = d.replace("https://", "").replace("http://", "").split("/")[0]
        all_targets.append(d)

        if include_subs:
            subs = subdomains.get_subdomains(base_domain)
            all_targets += [f"https://{sub}" for sub in subs]

    findings = []

    print(f"[bold cyan]Starting scan on:[/bold cyan] {', '.join([d.replace('https://','').replace('http://','') for d in domains])}")
    print(f"[italic]Total targets: {len(all_targets)}[/italic]\n")

    # Load wordlist if provided
    secrets = None
    if wordlist:
        try:
            with open(wordlist, "r") as f:
                secrets = [line.strip() for line in f if line.strip()]
            print(f"[bold yellow]Loaded {len(secrets)} secrets from wordlist.[/bold yellow]")
        except Exception as e:
            print(f"[red]Error loading wordlist: {e}[/red]")

    for target in all_targets:
        print(f"\n[underline]Scanning:[/underline] {target}")
        findings += open_directories.run(target)
        findings += exposed_files.run(target)
        findings += cors.run(target)
        findings += open_redirect.run(target)
        findings += security_headers.run(target)
        findings += robots_txt.run(target)
        findings += js_leaks.run(target)
        findings += jwt_token.run(target, secrets)  # Pass secrets to JWT check
        findings += web_cache_poisoning.run(target)
    report.save_report(base_domain, findings)

if __name__ == "__main__":
    app()
# This script is the main entry point for the Bounty-Lite tool.
# It scans a given domain for common vulnerabilities and saves the findings to a report.