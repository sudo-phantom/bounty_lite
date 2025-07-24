import httpx
import re
import jwt
from rich import print

COMMON_SECRETS = ["secret", "password", "admin", "123456", "jwtsecret"]

def run(domain):
    print("[bold green]Checking for JWT vulnerabilities...[/bold green]")
    results = []
    try:
        r = httpx.get(domain, timeout=5)
        # Look for JWTs in cookies or in the response
        tokens = []
        # Check cookies
        for cookie in r.cookies.jar:
            if re.match(r"^eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}$", cookie.value):
                tokens.append(cookie.value)
        # Check in response body
        found = re.findall(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", r.text)
        tokens += found

        for token in set(tokens):
            try:
                header = jwt.get_unverified_header(token)
                # Check for alg: none
                if header.get("alg", "").lower() == "none":
                    results.append({
                        "title": "JWT 'none' Algorithm Vulnerability",
                        "url": domain,
                        "description": "JWT token uses 'alg: none', allowing attackers to forge tokens without a signature.",
                        "summary": "If the server accepts JWTs with 'alg: none', authentication can be bypassed.",
                        "remediation": "Reject tokens with 'alg: none'. Always validate JWT signatures.",
                        "cwe_id": "CWE-287",
                        "proof": f"JWT token with alg:none found: {token}"
                    })
                # Try brute-forcing the secret
                for secret in COMMON_SECRETS:
                    try:
                        decoded = jwt.decode(token, secret, algorithms=[header.get("alg", "HS256")])
                        results.append({
                            "title": "JWT Weak Secret Vulnerability",
                            "url": domain,
                            "description": f"JWT token can be decoded with a weak secret: '{secret}'.",
                            "summary": "Weak secrets allow attackers to forge valid JWTs and impersonate users.",
                            "remediation": "Use strong, random secrets for signing JWTs.",
                            "cwe_id": "CWE-321",
                            "proof": f"JWT token decoded with secret '{secret}': {decoded}"
                        })
                        break
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception as e:
        print(f"[red]JWT check error: {e}[/red]")
    return results