import os
import sys
import subprocess
import datetime
import logging

# ---------------------------------
# Auto Install Required Packages
# ---------------------------------

required_packages = ["requests", "python-dotenv"]

for package in required_packages:
    try:
        __import__(package.replace("-", "_"))
    except ImportError:
        print(f"Installing missing package: {package}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# ---------------------------------
# Imports
# ---------------------------------

import requests
from dotenv import load_dotenv

# ---------------------------------
# Logging Setup
# ---------------------------------

log_file = f"qualys_auth_update_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

print(f"Log file created: {log_file}")

# ---------------------------------
# Load Environment Variables
# ---------------------------------

load_dotenv()

QUALYS_USERNAME = os.getenv("QUALYS_USERNAME")
QUALYS_PASSWORD = os.getenv("QUALYS_PASSWORD")

AUTH_RECORD_ID = os.getenv("AUTH_RECORD_ID")
TARGET_IPS = os.getenv("TARGET_IPS")

# Your Qualys URL
QUALYS_URL = "https://qualysapi.qualys.com/api/2.0/fo/authentication/record/"

# ---------------------------------
# Validation
# ---------------------------------

if not QUALYS_USERNAME or not QUALYS_PASSWORD:
    logging.error("Qualys credentials missing in .env")
    print("ERROR: Missing Qualys credentials")
    sys.exit(1)

if not AUTH_RECORD_ID:
    logging.error("AUTH_RECORD_ID missing")
    print("ERROR: AUTH_RECORD_ID missing")
    sys.exit(1)

if not TARGET_IPS:
    logging.error("TARGET_IPS missing")
    print("ERROR: TARGET_IPS missing")
    sys.exit(1)

# ---------------------------------
# Process IPs
# ---------------------------------

ip_list = [ip.strip() for ip in TARGET_IPS.split(",")]

print("\nIPs to add:")
for ip in ip_list:
    print(ip)

logging.info(f"IPs to add: {ip_list}")

# ---------------------------------
# Qualys API Call
# ---------------------------------

payload = {
    "action": "update",
    "id": AUTH_RECORD_ID,
    "ips": ",".join(ip_list)
}

headers = {
    "X-Requested-With": "Python Script"
}

print("\nSending request to Qualys API...")
logging.info("Sending API request")

try:

    response = requests.post(
        QUALYS_URL,
        data=payload,
        auth=(QUALYS_USERNAME, QUALYS_PASSWORD),
        headers=headers
    )

    print("\nStatus Code:", response.status_code)
    logging.info(f"Status Code: {response.status_code}")

    print("\nResponse:")
    print(response.text)

    logging.info(f"Response: {response.text}")

    if response.status_code == 200:
        print("\nAuthentication record updated successfully")
        logging.info("Authentication record updated successfully")

    else:
        print("\nFailed to update authentication record")
        logging.error("Failed API request")

except Exception as e:

    print("Error occurred:", str(e))
    logging.error(f"Script error: {str(e)}")
