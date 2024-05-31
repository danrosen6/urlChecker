1. Install virtual environment
pip install virtualenv

2. Create a Virtual Environment:
Navigate to your project directory and run:
virtualenv venv

3. Activate the Virtual Environment:
3.a In bash
source venv/bin/activate

3.b.1 For windows: If you don't want to change the global execution policy, 
you can alternatively run PowerShell with the execution policy 
temporarily adjusted for just that session:
powershell -ExecutionPolicy Bypass

3.b.2 In batch
venv\Scripts\activate

4. Ensure Your Virtual Environment is Activated:
You should see the name of your virtual environment (e.g., (venv))
at the beginning of your command line prompt. This indicates that 
any Python packages you install will only affect this virtual environment, 
rather than your global Python installation.

5. To install all dependencies 
in bash and batch
pip install -r requirements.txt 

To generate a requirements.txt 
in bash and batch
pip freeze > requirements.txt

6. Create .env file
create variable my_api_key and set it equal to the api key within a string

7. To run the file in terminal type
python fileName.py

VirusTotal API
Standard free public API
Usage	Must not be used in business workflows, commercial products or services.
Request rate	4 lookups / min
Daily quota	500 lookups / day
Monthly quota	15.5 K lookups / month