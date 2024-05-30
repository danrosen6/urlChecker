Install virtual environment
pip install virtualenv

Create a Virtual Environment:
Navigate to your project directory and run:
virtualenv venv

Activate the Virtual Environment:
In bash
source venv/bin/activate

If you don't want to change the global execution policy, 
you can alternatively run PowerShell with the execution policy 
temporarily adjusted for just that session:
powershell -ExecutionPolicy Bypass

In batch
venv\Scripts\activate

Ensure Your Virtual Environment is Activated:
You should see the name of your virtual environment (e.g., (venv))
at the beginning of your command line prompt. This indicates that 
any Python packages you install will only affect this virtual environment, 
rather than your global Python installation.

To run the file in terminal type
python fileName.py

To generate a requirements.txt 
in bash and batch
pip freeze > requirements.txt

To install all dependencies 
in bash and batch
pip install -r requirements.txt 