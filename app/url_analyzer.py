# MAIN MOTIVE: ectracts suspecious URLs from the mail and research about it witout OPENING it or visiting it

import re
from urllib.parse import urlparse, unquote


def extract_urls(text):
    """Extract URLs from email text without visiting them."""

    # Find URL-like strings beginning with HTTP or HTTPS.
    pattern = r'https?://[^\s<>"\']+'
    return re.findall(pattern, text, re.IGNORECASE)


def analyze_url(url):
    """Inspect a URL for basic suspicious characteristics."""

    findings = []

    # Parse the URL into components such as scheme and hostname.
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Flag URLs that use an IP address instead of a domain name.
    if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', hostname):
        findings.append("URL uses an IP address as its hostname.")

    # Flag insecure HTTP connections.
    if parsed.scheme.lower() == "http":
        findings.append("URL uses HTTP instead of HTTPS.")

    # Flag URLs containing a username or password before the hostname.
    if parsed.username or parsed.password:
        findings.append("URL contains credentials before the hostname.")

    # Flag URLs with percent-encoded characters for further inspection.
    if "%" in unquote(url) or re.search(r"%[0-9a-fA-F]{2}", url):
        findings.append("URL contains percent-encoded characters.")

    return {
        "url": url,
        "hostname": hostname,
        "findings": findings,
    }


if __name__ == "__main__":
    # Test using examples only; these URLs are not visited.
    sample_text = """
    Verify your account: https://example.com/verify
    Suspicious example: http://192.0.2.1/login
    """

    urls = extract_urls(sample_text)

    for url in urls:
        print(analyze_url(url))
