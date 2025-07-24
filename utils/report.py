import os
from datetime import datetime

def save_report(domain, findings):
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/{domain}.md"
    with open(filename, "w") as f:
        f.write(f"# Bounty-Lite Scan Report for `{domain}`\n")
        f.write(f"**Generated:** {datetime.utcnow().isoformat()} UTC\n\n")

        if not findings:
            f.write("_No findings detected._\n")
            return

        for finding in findings:
            f.write(f"## {finding['title']}\n")
            f.write(f"**URL:** `{finding['url']}`\n\n")
            f.write(f"**Description:** {finding['description']}\n\n")
            f.write("---\n")
    print(f"[bold green]Report saved to:[/bold green] {filename}")
# This function saves the scan report to a Markdown file in the 'reports' directory.