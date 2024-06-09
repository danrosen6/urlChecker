import requests
from requests.exceptions import RequestException
from dotenv import load_dotenv
import os
import time  # Use time.sleep for delaying in the thread, not affecting GUI responsiveness

# Load environment variables from a .env file, which includes sensitive data like API keys.
load_dotenv()

# Retrieve the API key stored as an environment variable for secure access to the API.
api_key = os.getenv("my_api_key")

def initiate_virus_total_analysis(url, callback):
    """Initiates analysis by submitting the URL to VirusTotal. 
    Uses the API key for authorization. Submits the URL and waits for a preliminary response."""
    headers = {'x-apikey': api_key}  # Authorization header with API key
    data = {'url': url}  # Data payload with the URL to be analyzed
    # Make a POST request to submit the URL for analysis
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=data)
    if response.status_code == 200:
        # If URL submission is successful, extract the analysis ID
        analysis_id = response.json().get('data', {}).get('id')
        time.sleep(15)  # Wait for 15 seconds to allow some analysis time before fetching results
        # Fetch results of the analysis using the analysis ID
        fetch_analysis_results(analysis_id, headers, callback)
    else:
        # Handle failed submission
        callback(f"Failed to fetch data: {response.status_code}\n")

def fetch_analysis_results(analysis_id, headers, callback):
    """Fetches the analysis results from VirusTotal using the analysis ID provided.
    Checks the status of the analysis and retrieves the results."""
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"  # URL to get analysis results
    response = requests.get(analysis_url, headers=headers)
    if response.status_code == 200:
        # If retrieval is successful, process and summarize the results
        callback(summarize_analysis(response.json()))
    else:
        # Handle error in fetching results
        callback(f"Failed to fetch analysis results: {response.status_code}\n")

def summarize_analysis(json_data):
    """Processes the JSON response from the analysis and generates a summary report.
    Extracts detailed results from each analysis engine and compiles them into a summary."""
    analysis_info = json_data['data']['attributes']  # General attributes of the analysis
    results = analysis_info['results']  # Individual results from each scanning engine
    stats = analysis_info['stats']  # Statistical summary of the analysis
    url_info = json_data['meta']['url_info']  # Metadata including the URL itself

    result = "URL Analysis Summary:\n"
    result += f"URL: {url_info['url']}\n"
    result += f"Status: {analysis_info['status']}\n"
    result += "Statistics:\n"
    result += f"Harmless: {stats['harmless']}, Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Undetected: {stats['undetected']}\n"

    # Detailed report for any engines detecting suspicious or malicious content
    result += "\nDetailed Report:\n"
    has_warnings = False
    for engine, details in results.items():
        if details['category'] in ['malicious', 'suspicious']:
            has_warnings = True
            result += f"{engine}: Category - {details['category']}, Result - {details['result']}\n"

    if not has_warnings:
        result += "No malicious or suspicious results found.\n"

    return result
