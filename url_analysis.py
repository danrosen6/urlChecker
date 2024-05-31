import requests
from urllib.parse import urlparse
import tldextract
import whois
import socket
from bs4 import BeautifulSoup

def analyze_url(url):
    print("Starting URL Analysis...")
    print("URL:", url)

    # Parse the URL to extract components like scheme, netloc, and path
    parsed_url = urlparse(url)
    # Extract the domain and suffix from the URL to handle subdomains, domains, and top-level domains
    domain_info = tldextract.extract(url)
    domain = f"{domain_info.domain}.{domain_info.suffix}"

    # Check if the URL uses HTTPS for secure communication
    print("URL uses HTTPS." if parsed_url.scheme == 'https' else "Warning: URL is not using HTTPS.")

    # Perform DNS lookup and WHOIS checks to get IP and registrar information
    perform_dns_and_whois_checks(parsed_url, domain)

    # Analyze the webpage content for redirects, security tags, and other security headers
    analyze_webpage_content(url)

def perform_dns_and_whois_checks(parsed_url, domain):
    # DNS lookup to resolve the domain name to an IP address
    try:
        ip_address = socket.gethostbyname(parsed_url.hostname)
        print("IP Address:", ip_address)
    except socket.gaierror:
        print("Failed to resolve domain to IP address.")

    # Retrieve WHOIS data for the domain to check the domain's registrar and creation date
    try:
        domain_whois = whois.whois(domain)
        print("Domain Registrar:", domain_whois.registrar)
        print("Creation Date:", domain_whois.creation_date)
    except Exception as e:
        print("WHOIS data unavailable or domain does not exist:", e)

def analyze_webpage_content(url):
    # Request the URL and parse the response content with BeautifulSoup
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Check if the URL was redirected from its original location
        if response.history:
            print("Redirects:")
            for resp in response.history:
                print(f"Redirected from {resp.url} to {resp.headers['Location']} with status {resp.status_code}")
            print("Final destination:", response.url)
        else:
            print("No redirects detected.")

        # Look for potentially malicious forms, iframes, and obfuscated JavaScript in the HTML content
        check_html_content(soup, url)

        # Print out any Content-Security-Policy header from the response for additional security
        print("Security Headers:", response.headers.get('Content-Security-Policy'))
    except requests.TooManyRedirects:
        print("Error: Too many redirects.")
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")

def check_html_content(soup, url):
    # Check HTML forms to see if their action attributes point to different domains, which can be suspicious
    forms = soup.find_all('form')
    for form in forms:
        if 'action' in form.attrs:
            action_url = urlparse(form.attrs['action'])
            if action_url.scheme and action_url.netloc and action_url.netloc != urlparse(url).netloc:
                print(f"Suspicious form action detected: {form.attrs['action']}")

    # Check iframes to ensure they do not contain potentially dangerous links or content
    iframes = soup.find_all('iframe')
    for iframe in iframes:
        print(f"Suspicious iframe detected: {iframe.get('src', 'No source')}")

    # Check for JavaScript that uses eval, a function often used to obfuscate potentially harmful code
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string and 'eval' in script.string:
            print("Obfuscated JavaScript detected")
