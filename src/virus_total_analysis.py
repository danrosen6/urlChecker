import requests
from requests.exceptions import RequestException
from dotenv import load_dotenv
import os
import time

# Load environment variables from a .env file, which includes sensitive data like API keys.
load_dotenv()

# Retrieve the API key stored as an environment variable for secure access to the API.
api_key = os.getenv("my_api_key")

def get_virus_total_report(url):
    """ Submits URL to VirusTotal for security analysis and returns the detailed results. """
    headers = {'x-apikey': api_key}  # Set headers for API authorization
    data = {'url': url}  # Data payload for the POST request
    # Send a POST request to initiate the URL analysis
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=data)
    if response.status_code == 200:
        result = ""
        time.sleep(15)  # Wait before requesting the analysis results
        analysis_id = response.json().get('data', {}).get('id')
        detailed_result = fetch_analysis_results(analysis_id, headers, 1)
        return result + (detailed_result if detailed_result else "Failed to fetch detailed analysis results.")
    else:
        return f"Failed to fetch data: {response.status_code}\n"

def fetch_analysis_results(analysis_id, headers, attempt):
    """ Fetches the analysis results from VirusTotal using the analysis ID provided. """
    result = ""
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    try:
        response = requests.get(analysis_url, headers=headers)
        if response.status_code == 200:
            result += summarize_analysis(response.json(), headers, attempt)
            return result
        else:
            result += f"Failed to fetch analysis results: {response.status_code}\n"
            return result
    except RequestException as e:
        result += f"An error occurred: {e}\n"
        return result

def summarize_analysis(json_data, headers, attempt):
    """ Processes the JSON response from the analysis and generates a summary report. """
    result = ""
    try:
        analysis_info = json_data['data']['attributes']
        status = analysis_info['status']

        # Check if analysis is still queued and handle retries
        if status == 'queued':
            if attempt <= 3:
                result += f"Analysis is queued. Waiting to retry... Attempt {attempt} out of 3\n"
                time.sleep(15)  # Delay for rechecking
                return fetch_analysis_results(json_data['data']['id'], headers, attempt + 1)
            else:
                result += "Maximum attempts reached. Analysis is still in queue.\n"
                return result

        # Compile results and statistics from the analysis
        results = analysis_info['results']
        stats = analysis_info['stats']
        url_info = json_data['meta']['url_info']

        result += "URL Analysis Summary:\n"
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

    except KeyError as e:
        result += f"Missing key in JSON data: {e}\n"

    return result
