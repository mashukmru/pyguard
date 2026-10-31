# PyGuard Commands

```powershell
# Run these commands from the PyGuard project folder.

# 1. Create and activate a virtual environment (skip creation if it already exists).
py -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies.
python -m pip install -r requirements.txt

# 3. Start the web application. Keep this terminal open.
python -m pyguard web

# 4. Open the dashboard in your browser.
Start-Process http://127.0.0.1:5000/dashboard
