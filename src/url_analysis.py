import requests
from urllib.parse import urlparse
import tldextract
import whois
import socket
from bs4 import BeautifulSoup
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def fetch_ip_info(ip_address):
    # Retrieve IP information API key from environment variable
    ipinfo_token = os.getenv('ip_info_key')  
    if not ipinfo_token:
        return "IPinfo token not found."
    try:
        # Send a GET request to the IPinfo API with the provided IP address and token
        response = requests.get(f'https://ipinfo.io/{ip_address}/json?token={ipinfo_token}')
        if response.status_code == 200:
            ip_info = response.json()
            location = f"{ip_info.get('city', 'Unknown')}, {ip_info.get('region', 'Unknown')}, {ip_info.get('country', 'Unknown')}"
            isp = ip_info.get('org', 'Unknown')
            return f"Location: {location}\nISP: {isp}\n"
        else:
            return f"IPinfo API error: {response.status_code}"
    except requests.RequestException as e:
        return f"Request failed: {e}"

def analyze_url(url):
    """ Analyze the given URL's security features including HTTPS usage, DNS resolution, WHOIS data, and web content."""
    result = f"URL: {url}\n"
    parsed_url = urlparse(url)  # Parse the URL to extract components such as scheme, netloc, etc.
    domain_info = tldextract.extract(url)  # Extract components from the URL to get domain and suffix
    domain = f"{domain_info.domain}.{domain_info.suffix}"  # Combine domain and suffix to form a full domain name

    # Check if the URL uses HTTPS for secure communication
    if parsed_url.scheme == 'https':
        result += "URL uses HTTPS.\n"
    else:
        result += "Warning: URL is not using HTTPS.\n"

    # Perform DNS lookup and WHOIS analysis and add the results to the output string
    result += perform_dns_and_whois_checks(parsed_url, domain)

    # Fetch and analyze the webpage's content and add the results to the output string
    result += analyze_webpage_content(url)

    return result

def perform_dns_and_whois_checks(parsed_url, domain):
    """ Perform DNS lookup and WHOIS analysis for the given domain."""
    result = ""
    try:
        # Resolve the domain to an IP address
        ip_address = socket.gethostbyname(parsed_url.hostname)
        result += f"IP Address: {ip_address}\n"
        # Fetch additional IP-related info using the IP address
        result += fetch_ip_info(ip_address)
    except socket.gaierror:
        result += "Failed to resolve domain to IP address.\n"

    try:
        # Retrieve WHOIS data for the domain
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
        # Send a GET request to fetch the webpage content
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')  # Parse the webpage content using BeautifulSoup

        # Document any redirects that occurred during the request
        if response.history:
            result += "Redirects:\n"
            for resp in response.history:
                redirect_location = resp.headers.get('Location', 'no redirect location provided')
                result += f"Redirected from {resp.url} to {redirect_location} with status {resp.status_code}\n"
            result += f"Final destination: {response.url}\n"
        else:
            result += "No redirects detected.\n"

        result += check_html_content(soup, url)  # Analyze HTML content for security issues

        # Check for the presence of important security headers in the HTTP response
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
    # Check forms for actions that post data to different domains
    forms = soup.find_all('form')
    for form in forms:
        if 'action' in form.attrs:
            action_url = urlparse(form.attrs['action'])
            if action_url.scheme and action_url.netloc and action_url.netloc != urlparse(url).netloc:
                result += f"Suspicious form action detected: {form.attrs['action']}\n"

    # Check iframes for potentially malicious sources
    iframes = soup.find_all('iframe')
    for iframe in iframes:
        iframe_src = iframe.get('src', 'No source provided')
        result += f"Suspicious iframe detected: {iframe_src}\n"

    # Check JavaScripts for potentially malicious code
    scripts = soup.find_all('script')
    for script in scripts:
        if script.string and 'eval' in script.string:
            result += "Obfuscated JavaScript detected\n"

    return result
