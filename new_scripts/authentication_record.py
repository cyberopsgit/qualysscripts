import os
import sys
import subprocess
import datetime
import logging

# ---------------------------------------------------
# Auto install required modules if missing
# ---------------------------------------------------

required_packages = {
    "requests": "requests",
    "python-dotenv": "dotenv"
}

for package, module in required_packages.items():
    try:
        __import__(module)
    except ImportError:
        print(f"Installing missing package: {package}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# ---------------------------------------------------
# Imports after installation
# ---------------------------------------------------

import requests
from dotenv import load_dotenv
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------
# Logging Setup
# ---------------------------------------------------

log_file = f"qualys_auth_update_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

print(f"\nLog file created: {log_file}")

# ---------------------------------------------------
# Load environment variables
# ---------------------------------------------------

load_dotenv()

QUALYS_USERNAME = os.getenv("QUALYS_USERNAME")
QUALYS_PASSWORD = os.getenv("QUALYS_PASSWORD")
AUTH_RECORD_ID = os.getenv("AUTH_RECORD_ID")
TARGET_IPS = os.getenv("TARGET_IPS")

QUALYS_URL = "https://qualysapi.qualys.com/api/2.0/fo/authentication/record/"

# ---------------------------------------------------
# Validation
# ---------------------------------------------------

if not QUALYS_USERNAME or not QUALYS_PASSWORD:
    print("ERROR: Qualys credentials missing in .env")
    logging.error("Missing Qualys credentials")
    sys.exit(1)

if not AUTH_RECORD_ID:
    print("ERROR: AUTH_RECORD_ID missing")
    logging.error("AUTH_RECORD_ID missing")
    sys.exit(1)

if not TARGET_IPS:
    print("ERROR: TARGET_IPS missing")
    logging.error("TARGET_IPS missing")
    sys.exit(1)

# ---------------------------------------------------
# Process IPs
# ---------------------------------------------------

ip_list = [ip.strip() for ip in TARGET_IPS.split(",")]

print("\nIPs to add to authentication record:")

for ip in ip_list:
    print(ip)

logging.info(f"IPs provided: {ip_list}")

# ---------------------------------------------------
# Qualys API request
# ---------------------------------------------------

payload = {
    "action": "update",
    "id": AUTH_RECORD_ID,
    "ips": ",".join(ip_list)
}

headers = {
    "X-Requested-With": "Python Script"
}

print("\nSending request to Qualys API...")
logging.info("Sending request to Qualys API")

try:

    response = requests.post(
        QUALYS_URL,
        data=payload,
        auth=(QUALYS_USERNAME, QUALYS_PASSWORD),
        headers=headers,
        verify=False
    )

    print("\nStatus Code:", response.status_code)
    logging.info(f"Status Code: {response.status_code}")

    print("\nAPI Response:")
    print(response.text)

    logging.info(f"API Response: {response.text}")

    if response.status_code == 200:
        print("\nAuthentication record updated successfully")
        logging.info("Authentication record updated successfully")

    else:
        print("\nFailed to update authentication record")
        logging.error("Failed to update authentication record")

except Exception as e:

    print("\nError occurred:", str(e))
    logging.error(f"Script error: {str(e)}")
