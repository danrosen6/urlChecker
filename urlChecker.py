import requests
from dotenv import load_dotenv
import os

# Load environment variables from a .env file located in the same directory as this script.
load_dotenv()

# Retrieve the API key stored in an environment variable for added security.
api_key = os.getenv("my_api_key")

def get_virus_total_report(url):
    # Headers dictionary containing the API key necessary for authentication with the VirusTotal API.
    headers = {'x-apikey': api_key}
    
    # Data dictionary containing the URL to be analyzed.
    data = {'url': url}
    
    # Send a POST request to the VirusTotal API to submit the URL for analysis.
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=data)

    # Check if the response status code is 200 (OK), which means the request was successful.
    if response.status_code == 200:
        # Extract the analysis ID from the response to use in a subsequent request.
        analysis_id = response.json().get('data', {}).get('id')
        # Fetch detailed analysis results using the analysis ID.
        return fetch_analysis_results(analysis_id, headers)
    else:
        # Print an error message if the request was not successful.
        print(f"Failed to fetch data: {response.status_code}")
        return None

def fetch_analysis_results(analysis_id, headers):
    # Construct the URL to fetch the analysis results using the analysis ID.
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    # Send a GET request to retrieve the detailed analysis results.
    response = requests.get(analysis_url, headers=headers)
    
    # Check if the response status code is 200 (OK).
    if response.status_code == 200:
        # Return the JSON response containing the analysis results.
        return summarize_analysis(response.json())
    else:
        # Print an error message if the request to fetch analysis results was not successful.
        print(f"Failed to fetch analysis results: {response.status_code}")
        return None
    
def summarize_analysis(json_data):
        
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
        print(f"Missing key in JSON data: {e}")

def prompt_for_detail():
    """
    Prompts the user to decide if they want a more detailed report.
    Returns True if user wants more details, False otherwise.
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
    Displays a detailed report based on the results dictionary.
    """
    print("Detailed Report:")
    for engine, details in results.items():
        print(f"{engine}: Category - {details['category']}, Result - {details['result']}")
           
def main():
    # Prompt the user to enter a URL to check.
    user_url = input("Enter the URL to check: ")
    
    # Call the function to get the virus total report for the entered URL.
    get_virus_total_report(user_url)

# This ensures the main function is executed only when the script is run directly, not when imported.
if __name__ == "__main__":
    main()
