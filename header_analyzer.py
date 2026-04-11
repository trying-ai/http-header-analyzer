#!/usr/bin/env python3
"""
HTTP Header Analyzer
CLI tool that inspects HTTP response headers and flags missing baseline security headers.
"""

import argparse
import sys
from urllib.parse import urlparse

import requests


def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        return 'https://' + url
    return url


def analyze_headers(url):
    normalized_url = normalize_url(url)

    try:
        response = requests.get(normalized_url, timeout=10, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        if normalized_url.startswith('https://'):
            fallback_url = 'http://' + normalized_url.removeprefix('https://')
            try:
                print(f"[WARN] HTTPS request failed, retrying with HTTP: {fallback_url}")
                response = requests.get(fallback_url, timeout=10, allow_redirects=True)
            except requests.exceptions.RequestException as fallback_exc:
                print(f"Error making request: {fallback_exc}")
                sys.exit(1)
        else:
            print(f"Error making request: {exc}")
            sys.exit(1)

    headers = response.headers

    security_headers = {
        'Content-Security-Policy': 'Content Security Policy',
        'Strict-Transport-Security': 'HTTP Strict Transport Security',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-Content-Type-Options': 'MIME Sniffing Protection',
        'Referrer-Policy': 'Referrer Policy',
        'Permissions-Policy': 'Browser Feature Policy',
    }

    final_url = response.url
    parsed = urlparse(final_url)

    print(f"Analyzing headers for: {normalized_url}")
    print(f"Final URL: {final_url}")
    print(f"Status Code: {response.status_code}")
    print("-" * 60)

    missing_count = 0
    for header, description in security_headers.items():
        if header in headers:
            print(f"[OK] {header} ({description})")
        else:
            print(f"[MISSING] {header} ({description})")
            missing_count += 1

    print("-" * 60)

    if parsed.scheme != 'https':
        print("[WARN] Final response is not HTTPS. Sensitive traffic may be exposed.")

    if 'Server' in headers:
        print(f"[INFO] Server header exposed: {headers['Server']}")

    if missing_count == 0:
        print("Result: Baseline security headers are present.")
    else:
        print(f"Result: {missing_count} recommended security headers are missing.")


def main():
    parser = argparse.ArgumentParser(
        description='HTTP Header Analyzer - Check for missing security headers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python header_analyzer.py https://example.com
  python header_analyzer.py example.com
        """,
    )
    parser.add_argument('url', help='URL to analyze (with or without http/https)')

    args = parser.parse_args()
    analyze_headers(args.url)


if __name__ == '__main__':
    main()
