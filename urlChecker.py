import requests
from dotenv import load_dotenv
import os

load_dotenv()  # This loads the .env file at the project root
api_key = os.getenv("apiKey")

def get_virus_total_report(url):
    headers = {'x-apikey': api_key}
    data = {'url': url}
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=data)

    if response.status_code == 200:
        analysis_id = response.json().get('data', {}).get('id')
        return fetch_analysis_results(analysis_id, headers)
    else:
        print(f"Failed to fetch data: {response.status_code}")
        return None

def fetch_analysis_results(analysis_id, headers):
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    response = requests.get(analysis_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch analysis results: {response.status_code}")
        return None

def main():
    user_url = input("Enter the URL to check: ")
    report = get_virus_total_report(user_url)
    if report:
        print(report)  # You might want to format this better based on what you need
    else:
        print("No valid response received.")

if __name__ == "__main__":
    main()
