from url_analysis import analyze_url
from virus_total_analysis import get_virus_total_report

def main():
    # User input for URL to be checked.
    url = input("Enter the URL to check: ")

    analyze_url(url)
    
    # Function call to begin the process of obtaining and displaying the VirusTotal report.
    get_virus_total_report(url)

# Ensure that main function is called only when the script is executed directly, not when imported.
if __name__ == "__main__":
    main()