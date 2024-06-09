import requests
from requests.exceptions import RequestException
from dotenv import load_dotenv
import os
import time  # Import time module to use sleep for delays

# Load environment variables from a .env file to securely access API keys.
load_dotenv()

# Retrieve the VirusTotal API key from an environment variable for secure API access.
api_key = os.getenv('vt_key')

def initiate_virus_total_analysis(url, callback):
    """
    Initiates analysis by submitting the URL to the VirusTotal API.
    It uses an API key for authorization, submits the URL, and handles the initial response.
    """
    headers = {'x-apikey': api_key}  # Set up the authorization header with the API key.
    data = {'url': url}  # Data payload with the URL to analyze.
    
    # Make a POST request to submit the URL to VirusTotal.
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=data)
    if response.status_code == 200:
        # Extract the analysis ID if URL submission is successful.
        analysis_id = response.json().get('data', {}).get('id')
        time.sleep(15)  # Delay for 15 seconds to allow time for the analysis to begin.
        # Fetch the results using the analysis ID.
        fetch_analysis_results(analysis_id, headers, callback)
    else:
        # Handle any errors in submission.
        callback(f"Failed to fetch data: {response.status_code}\n")

def fetch_analysis_results(analysis_id, headers, callback):
    """
    Fetches analysis results from VirusTotal using the provided analysis ID.
    It retrieves the status and results of the analysis.
    """
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"  # Endpoint to get analysis results.
    response = requests.get(analysis_url, headers=headers)
    if response.status_code == 200:
        # Process the successful retrieval of analysis results.
        callback(summarize_analysis(response.json()))
    else:
        # Handle errors in fetching the analysis results.
        callback(f"Failed to fetch analysis results: {response.status_code}\n")

def summarize_analysis(json_data):
    """
    Processes the JSON response from the analysis and generates a summary report.
    Extracts and compiles results from various analysis engines.
    """
    analysis_info = json_data['data']['attributes']  # Extract general attributes of the analysis.
    results = analysis_info['results']  # Individual results from each scan engine.
    stats = analysis_info['stats']  # Statistical summary of the analysis.
    url_info = json_data['meta']['url_info']  # Metadata including the URL.

    # Compile a summary report of the URL analysis.
    result = "URL Analysis Summary:\n"
    result += f"URL: {url_info['url']}\n"
    result += f"Status: {analysis_info['status']}\n"
    result += "Statistics:\n"
    result += f"Harmless: {stats['harmless']}, Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Undetected: {stats['undetected']}\n"

    # Generate detailed reports for engines detecting suspicious or malicious content.
    result += "\nDetailed Report:\n"
    has_warnings = False
    for engine, details in results.items():
        if details['category'] in ['malicious', 'suspicious']:
            has_warnings = True
            result += f"{engine}: Category - {details['category']}, Result - {details['result']}\n"

    if not has_warnings:
        result += "No malicious or suspicious results found.\n"

    return result
