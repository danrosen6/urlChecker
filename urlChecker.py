import requests
from requests.exceptions import RequestException
from dotenv import load_dotenv
import os

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
        analysis_id = response.json().get('data', {}).get('id')
        return fetch_analysis_results(analysis_id, headers)
    else:
        # Handle unsuccessful responses by logging the HTTP status code.
        print(f"Failed to fetch data: {response.status_code}")
        return None

def fetch_analysis_results(analysis_id, headers):
    # Construct the specific URL to fetch the detailed analysis results using the obtained analysis ID.
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    try:
        # Make a GET request to retrieve the detailed analysis results.
        response = requests.get(analysis_url, headers=headers)
        if response.status_code == 200:
            return summarize_analysis(response.json())
        else:
            print(f"Failed to fetch analysis results: {response.status_code}")
            return None
    except RequestException as e:
        # Log any exceptions that occur during the GET request, typically related to network issues.
        print(f"An error occurred: {e}")
        return None
    
def summarize_analysis(json_data):
    # Extract and summarize the relevant data from the JSON response.
    try:
        analysis_info = json_data['data']['attributes']
        results = analysis_info['results']
        stats = analysis_info['stats']
        url_info = json_data['meta']['url_info']

        print("URL Analysis Summary:")
        print(f"URL: {url_info['url']}")
        print(f"Status: {analysis_info['status']}")
        print("Statistics:")
        print(f"Harmless: {stats['harmless']}, Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Undetected: {stats['undetected']}")

        if prompt_for_detail():
            display_detailed_report(results)
    except KeyError as e:
        # Handle missing keys in JSON response, which might indicate changes in API response structure.
        print(f"Missing key in JSON data: {e}")

def prompt_for_detail():
    """
    Prompt the user to decide if they want a more detailed report.
    Return True if the user wants more details, False otherwise.
    """
    while True:
        user_input = input("Do you want a more detailed report? (y/n): ").lower()
        if user_input == 'y':
            return True
        elif user_input == 'n':
            return False
        else:
            print("Invalid input, please enter 'y' or 'n'.")

def display_detailed_report(results):
    """
    Displays a detailed report based on the results dictionary provided by the analysis.
    Each antivirus engine result is listed with its category and detection result.
    """
    print("Detailed Report:")
    for engine, details in results.items():
        print(f"{engine}: Category - {details['category']}, Result - {details['result']}")

def main():
    # User input for URL to be checked.
    user_url = input("Enter the URL to check: ")
    
    # Function call to begin the process of obtaining and displaying the VirusTotal report.
    get_virus_total_report(user_url)

# Ensure that main function is called only when the script is executed directly, not when imported.
if __name__ == "__main__":
    main()