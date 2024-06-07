import requests
from urllib.parse import urlparse
import tldextract
import whois
import socket
from bs4 import BeautifulSoup

def analyze_url(url):
    """ Analyze the given URL's security features including HTTPS usage, DNS resolution, WHOIS data, and web content."""
    result = f"URL: {url}\n"  # Start building the result string

    parsed_url = urlparse(url)  # Parse the URL to get components
    domain_info = tldextract.extract(url)  # Extract the domain and suffix
    domain = f"{domain_info.domain}.{domain_info.suffix}"  # Construct full domain name

    # Check if the URL uses HTTPS
    if parsed_url.scheme == 'https':
        result += "URL uses HTTPS.\n"
    else:
        result += "Warning: URL is not using HTTPS.\n"

    # Perform DNS lookup and WHOIS analysis, then add results to output string
    result += perform_dns_and_whois_checks(parsed_url, domain)

    # Analyze the webpage content and add results to output string
    result += analyze_webpage_content(url)

    return result

def perform_dns_and_whois_checks(parsed_url, domain):
    """ Perform DNS lookup and WHOIS analysis for the given domain."""
    result = ""
    try:
        # Try resolving the domain to an IP address
        ip_address = socket.gethostbyname(parsed_url.hostname)
        result += f"IP Address: {ip_address}\n"
    except socket.gaierror:
        result += "Failed to resolve domain to IP address.\n"

    try:
        # Retrieve and format WHOIS data
        domain_whois = whois.whois(domain)
        result += f"Domain Registrar: {domain_whois.registrar}\n"
        result += f"Creation Date: {domain_whois.creation_date}\n"
    except Exception as e:
        result += f"WHOIS data unavailable or domain does not exist: {e}\n"

    return result

def analyze_webpage_content(url):
    """ Fetch and analyze webpage content for potential security issues."""
    result = ""
    try:
        response = requests.get(url, timeout=10)  # Fetch the webpage
        soup = BeautifulSoup(response.content, 'html.parser')  # Parse webpage content

        # Check and document any redirects that occurred
        if response.history:
            result += "Redirects:\n"
            for resp in response.history:
                result += f"Redirected from {resp.url} to {resp.headers['Location']} with status {resp.status_code}\n"
            result += f"Final destination: {response.url}\n"
        else:
            result += "No redirects detected.\n"

        result += check_html_content(soup, url)  # Analyze the HTML content for security issues

        # Check for the presence of important security headers
        headers_to_check = ['Content-Security-Policy', 'X-XSS-Protection', 'X-Frame-Options', 'Strict-Transport-Security']
        found_headers = {h: response.headers.get(h) for h in headers_to_check if response.headers.get(h)}
        if found_headers:
            result += "Security Headers Found:\n"
            for header, value in found_headers.items():
                result += f"{header}: {value}\n"
        else:
            result += "Important security headers missing.\n"

    except requests.TooManyRedirects:
        result += "Error: Too many redirects.\n"
    except requests.RequestException as e:
        result += f"Error fetching URL: {e}\n"

    return result


def check_html_content(soup, url):
    """ Check HTML content for potentially malicious elements like forms, iframes, and scripts."""
    result = ""
    # Check forms for suspicious actions
    forms = soup.find_all('form')
    for form in forms:
        if 'action' in form.attrs:
            action_url = urlparse(form.attrs['action'])
            # Flag forms that post data to different domains
            if action_url.scheme and action_url.netloc and action_url.netloc != urlparse(url).netloc:
                result += f"Suspicious form action detected: {form.attrs['action']}\n"

    # Check iframes for potentially malicious sources
    iframes = soup.find_all('iframe')
    for iframe in iframes:
        result += f"Suspicious iframe detected: {iframe.get('src', 'No source')}\n"

    # Check JavaScripts for potentially malicious code
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string and 'eval' in script.string:
            result += "Obfuscated JavaScript detected\n"

    return result
