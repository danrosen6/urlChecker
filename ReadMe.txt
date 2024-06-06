Python project to analyze URLs for phishing scams.


Project Setup Guide

1. Install Virtual Environment

    First, you need to install the `virtualenv` package if 
    it is not already installed. This package allows you to 
    create isolated Python environments. Run the following 
    command in your terminal:

    pip install virtualenv


2. Create a Virtual Environment

    Navigate to your project directory in the terminal. 
    Create a virtual environment named `venv` by running:

    In terminal enter:
        virtualenv venv

    This command creates a directory named `venv` where the 
    virtual environment files are stored.


3. Activate the Virtual Environment

    To activate the virtual environment, use the appropriate
    command for your operating system:

    For Bash (Linux/macOS):
        source venv/bin/activate

    For Windows:

        Using PowerShell without changing the global 
        execution policy. Run PowerShell with the execution policy
        temporarily adjusted for just that session. This can be done 
        from the same terminal. Enter the following:
            powershell -ExecutionPolicy Bypass

        Then enter the following:
            venv\Scripts\activate


4. Ensure Your Virtual Environment is Activated

    After activation, you should see `(venv)` at the beginning of your
    command line prompt. This indicates that the virtual environment is 
    active, and any Python packages installed will only affect this 
    virtual environment.

5. Install Project Dependencies

    Install all required dependencies using the following command:
        pip install -r requirements.txt

    To generate a `requirements.txt` file that lists all current 
    project dependencies, run:
        pip freeze > requirements.txt

6. Create a `.env` File

    Create a `.env` file in your project directory. Add configuration 
    settings and secrets here. This will be used to store the api
    for VirusTotal.
        my_api_key="YOUR_API_KEY_HERE"

    Can be acquired here
    https://www.virustotal.com/gui/my-apikey

7. Running Your Application

    With the virtual environment activated, change directory to src and 
    run Python scripts as follows. This ensures that the script uses the 
    correct environment settings:

    cd src

    For this specific project, start with:
        python main.py

VirusTotal API Information

    Type: Standard free public API
    Usage Restrictions: Must not be used in business workflows, 
        commercial products, or services.
    Request Rate: 4 lookups per minute
    Daily Quota: 500 lookups per day
    Monthly Quota: 15,500 lookups per month
