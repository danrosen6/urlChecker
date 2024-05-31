import requests
from urllib.parse import urlparse, parse_qs
import tldextract
import whois
import socket

def analyze_url(url):
    print("Starting URL Analysis...")
    print("URL:", url)

    # Parse the URL and extract components
    parsed_url = urlparse(url)
    domain_info = tldextract.extract(url)

    # Check the protocol
    if parsed_url.scheme != 'https':
        print("Warning: URL is not using HTTPS.")
    else:
        print("URL uses HTTPS.")

    # Extract and print domain details
    domain = f"{domain_info.domain}.{domain_info.suffix}"
    print("Domain:", domain)

    # Check for IP address directly in URL
    if parsed_url.hostname.replace('.', '').isdigit():
        print("URL contains an IP address instead of a domain name.")
    
    # Perform DNS lookup to find IP address
    try:
        ip_address = socket.gethostbyname(parsed_url.hostname)
        print("IP Address:", ip_address)
    except socket.gaierror:
        print("Failed to resolve domain to IP address.")

    # Get WHOIS information
    try:
        domain_whois = whois.whois(domain)
        print("Domain Registrar:", domain_whois.registrar)
        print("Creation Date:", domain_whois.creation_date)
    except:
        print("WHOIS data unavailable or domain does not exist.")

    # Check the path and query
    if parsed_url.path:
        print("Path:", parsed_url.path)
    if parsed_url.query:
        query_params = parse_qs(parsed_url.query)
        print("Query Parameters:", query_params)

    # Check for redirects
    try:
        response = requests.get(url)
        if response.history:
            print("Redirects:")
            for resp in response.history:
                print("Redirected from", resp.url)
            print("Final destination:", response.url)
        else:
            print("No redirects detected.")
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")

