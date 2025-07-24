import requests
from urllib.parse import urljoin
from xml.etree import ElementTree

def check_sitemap_xml(base_url):
    result = {
        "url": urljoin(base_url, "/sitemap.xml"),
        "status": "not found",
        "discovered_paths": [],
        "interesting": [],
        "remediation": "Restrict sitemap access or limit entries to public-facing content.",
        "cwe_id": "CWE-200"
    }

    sitemap_url = result["url"]

    try:
        response = requests.get(sitemap_url, timeout=10)
        if response.status_code == 200 and "xml" in response.headers.get("Content-Type", ""):
            result["status"] = "found"
            tree = ElementTree.fromstring(response.content)
            interesting_keywords = ["admin", "test", "dev", "backup", "internal"]

            for url in tree.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc"):
                path = url.text.strip()
                result["discovered_paths"].append(path)
                if any(keyword in path.lower() for keyword in interesting_keywords):
                    result["interesting"].append(path)
                    # When you append a finding, include 'cwe_id' and 'proof'
                    finding = {
                        "title": "Sensitive Path in Sitemap",
                        "url": path,
                        "description": "Path in sitemap.xml may expose sensitive content.",
                        "summary": "...",
                        "remediation": result["remediation"],
                        "cwe_id": result["cwe_id"],
                        "proof": f"Discovered in sitemap: {sitemap_url}"
                    }
                    result["findings"].append(finding)

    except Exception as e:
        result["error"] = str(e)

    return result

# Example usage
if __name__ == "__main__":
    from pprint import pprint
    pprint(check_sitemap_xml("https://example.com"))
# This script checks for the presence of a sitemap.xml file on a given domain.
# It retrieves the sitemap, parses it, and identifies any paths that may be sensitive or interesting.