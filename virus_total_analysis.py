import requests
from requests.exceptions import RequestException
from dotenv import load_dotenv
import os
import time
from continue_prompt import prompt_to_continue

# Load sensitive data securely using environment variables from a .env file.
load_dotenv()

# Retrieve the API key from environment variables for secure API requests.
api_key = os.getenv("my_api_key")

def get_virus_total_report(url):
    # Configure headers for VirusTotal API requests using the retrieved API key.
    headers = {'x-apikey': api_key}
    
    # Prepare data for the POST request to submit the URL for analysis.
    data = {'url': url}
    
    # Submit the URL for initial analysis and handle the response.
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=data)

    # Check response status and proceed to retrieve detailed analysis results.
    if response.status_code == 200:
        print("\nAnalyzing with VirusTotal... Please wait 15 seconds")
        time.sleep(15) # Delay to allow time for the initial analysis.
        analysis_id = response.json().get('data', {}).get('id')
        return fetch_analysis_results(analysis_id, headers, 1)
    else:
        print(f"Failed to fetch data: {response.status_code}")
        return None

def fetch_analysis_results(analysis_id, headers, attempt):
    # Fetch detailed analysis results using the provided analysis ID.
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    try:
        response = requests.get(analysis_url, headers=headers)
        if response.status_code == 200:
            return summarize_analysis(response.json(), headers, attempt)
        else:
            print(f"Failed to fetch analysis results: {response.status_code}")
            return None
    except RequestException as e:
        print(f"An error occurred: {e}")
        return None
    
def summarize_analysis(json_data, headers, attempt):
    # Extract and summarize key information from the JSON response.
    try:
        analysis_info = json_data['data']['attributes']
        status = analysis_info['status']
        
        # Handle queued analysis status by retrying up to three times.
        if status == 'queued':
            if attempt <= 3:
                print(f"Analysis is queued. Waiting to retry... Attempt {attempt} out of 3")
                time.sleep(15)
                return fetch_analysis_results(json_data['data']['id'], headers, attempt + 1)
            else:
                print("Maximum attempts reached. Analysis is still in queue.")
                return None

        results = analysis_info['results']
        stats = analysis_info['stats']
        url_info = json_data['meta']['url_info']

        print("\nURL Analysis Summary:")
        print(f"URL: {url_info['url']}")
        print(f"Status: {analysis_info['status']}")
        print("Statistics:")
        print(f"Harmless: {stats['harmless']}, Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Undetected: {stats['undetected']}")

        print("Do you want a more detailed report? (y/n): ")
        if prompt_to_continue():
            display_detailed_report(results)
    except KeyError as e:
        print(f"Missing key in JSON data: {e}")

def display_detailed_report(results):
    # Display results from engines that flagged the URL as malicious or suspicious.
    print("Detailed Report:")
    has_warnings = False

    for engine, details in results.items():
        if details['category'] in ['malicious', 'suspicious']:
            has_warnings = True
            print(f"{engine}: Category - {details['category']}, Result - {details['result']}")

    if not has_warnings:
        print("No malicious or suspicious results found.")
    
    print("\nDo you want to see results from all engines? (y/n): ")
    if prompt_to_continue():
        for engine, details in results.items():
            print(f"{engine}: Category - {details['category']}, Result - {details['result']}")
