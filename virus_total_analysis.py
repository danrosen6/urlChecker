import requests
from requests.exceptions import RequestException
from dotenv import load_dotenv
import os
import time
from continue_prompt import prompt_to_continue

# Load environment variables from a .env file located in the same directory as this script to keep sensitive data secure.
load_dotenv()

# Retrieve the API key stored in an environment variable for added security. Ensure 'my_api_key' is correctly set in your .env file.
api_key = os.getenv("my_api_key")

def get_virus_total_report(url):
    # Prepare headers with the API key for authentication purposes when making requests to the VirusTotal API.
    headers = {'x-apikey': api_key}
    
    # The data dictionary holds the URL to be analyzed, prepared for the POST request.
    data = {'url': url}
    
    # Perform a POST request to the VirusTotal API to submit the URL for initial analysis and obtain an analysis ID.
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=data)

    # Successful response check; continue to retrieve detailed analysis using the received analysis ID.
    if response.status_code == 200:
        print("\nAnalyzing with VirusTotal... Please wait 15 seconds")
        time.sleep(15) # Give time for virus total to analyze. Helps to limit # of api calls.
        analysis_id = response.json().get('data', {}).get('id')
        return fetch_analysis_results(analysis_id, headers, 1)
    else:
        # Handle unsuccessful responses by logging the HTTP status code.
        print(f"Failed to fetch data: {response.status_code}")
        return None

def fetch_analysis_results(analysis_id, headers, attempt):
    # Construct the specific URL to fetch the detailed analysis results using the obtained analysis ID.
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    try:
        # Make a GET request to retrieve the detailed analysis results.
        response = requests.get(analysis_url, headers=headers)
        if response.status_code == 200:
            return summarize_analysis(response.json(), headers, attempt)
        else:
            print(f"Failed to fetch analysis results: {response.status_code}")
            return None
    except RequestException as e:
        # Log any exceptions that occur during the GET request, typically related to network issues.
        print(f"An error occurred: {e}")
        return None
    
def summarize_analysis(json_data, headers, attempt):
    # Extract and summarize the relevant data from the JSON response.
    try:
        analysis_info = json_data['data']['attributes']
        status = analysis_info['status']
        
        # Check if the analysis status is 'queued'
        if status == 'queued':
            if attempt <= 3:
                print(f"Analysis is queued. Waiting to retry... Attempt {attempt} out of 3")
                time.sleep(15)  # Wait for 15 seconds before retrying
                return fetch_analysis_results(json_data['data']['id'], headers, attempt + 1)
            else:
                print("Maximimum attempts reached. Analysis is still in queue.")
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
        # Handle missing keys in JSON response, which might indicate changes in API response structure.
        print(f"Missing key in JSON data: {e}")

def rescan_url(analysis_id, headers):
    """
    Rescan the URL using the given analysis ID.
    """
    rescan_url = f"https://www.virustotal.com/api/v3/urls/{analysis_id}/analyse"
    try:
        response = requests.post(rescan_url, headers=headers)
        if response.status_code == 200:
            print("URL rescan initiated successfully.")
            time.sleep(15)  # Wait for the rescan to complete
            return fetch_analysis_results(analysis_id, headers, 1)
        else:
            print(f"Failed to initiate rescan: {response.status_code}")
            return None
    except RequestException as e:
        print(f"An error occurred during rescan: {e}")
        return None


def display_detailed_report(results):
    """
    Displays a detailed report focusing on malicious or suspicious findings. If no such findings exist,
    the user is prompted to display all engines' results.
    """
    print("Detailed Report:")
    has_warnings = False

    # First, display only malicious or suspicious results
    for engine, details in results.items():
        if details['category'] in ['malicious', 'suspicious']:
            has_warnings = True
            print(f"{engine}: Category - {details['category']}, Result - {details['result']}")

    if not has_warnings:
        print("No malicious or suspicious results found.")
    
    # Ask user if they want to see results from all engines
    print("\nDo you want to see results from all engines? (y/n): ")
    if prompt_to_continue():
        for engine, details in results.items():
            print(f"{engine}: Category - {details['category']}, Result - {details['result']}")