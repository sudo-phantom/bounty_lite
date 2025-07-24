import typer
from checks import open_directories, exposed_files, cors,jwt_token, open_redirect, security_headers, robots_txt, js_leaks
from utils import report, subdomains
from rich import print
from datetime import datetime

app = typer.Typer(help="Bounty-Lite: Low-hanging fruit bug bounty recon tool.")

@app.command()
def scan(domain: str, include_subs: bool = True):
    if not domain.startswith("http"):
        domain = "https://" + domain

    base_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    all_targets = [domain]

    if include_subs:
        subs = subdomains.get_subdomains(base_domain)
        all_targets += [f"https://{sub}" for sub in subs]

    findings = []

    print(f"[bold cyan]Starting scan on:[/bold cyan] {base_domain}")
    print(f"[italic]Total targets: {len(all_targets)}[/italic]\n")

    for target in all_targets:
        print(f"\n[underline]Scanning:[/underline] {target}")
        findings += open_directories.run(target)
        findings += exposed_files.run(target)
        findings += cors.run(target)
        findings += open_redirect.run(target)
        findings += security_headers.run(target)
        findings += robots_txt.run(target)
        findings += js_leaks.run(target)
        findings += jwt_token.run(target)    
    report.save_report(base_domain, findings)

if __name__ == "__main__":
    app()
# This script is the main entry point for the Bounty-Lite tool.
# It scans a given domain for common vulnerabilities and saves the findings to a report.