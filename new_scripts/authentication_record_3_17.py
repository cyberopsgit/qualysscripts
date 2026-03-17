import os
import sys
import subprocess
import datetime
import logging

# ---------------------------------
# Auto Install Required Packages
# ---------------------------------
required_packages = ["requests", "python-dotenv", "urllib3"]

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
import urllib3
from dotenv import load_dotenv
import xml.etree.ElementTree as ET

# Suppress the InsecureRequestWarning caused by verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------
# Logging Setup
# ---------------------------------
log_file = f"qualys_oracle_update_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

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

# ORACLE SPECIFIC ENDPOINT
QUALYS_URL = "https://qualysapi.qualys.com/api/2.0/fo/auth/oracle/"

# ---------------------------------
# Validation
# ---------------------------------
if not all([QUALYS_USERNAME, QUALYS_PASSWORD, AUTH_RECORD_ID, TARGET_IPS]):
    error_msg = "Missing required environment variables in the .env file. Check credentials, ID, and IPs."
    logging.error(error_msg)
    print(f"ERROR: {error_msg}")
    sys.exit(1)

# ---------------------------------
# Process IPs
# ---------------------------------
ip_list = [ip.strip() for ip in TARGET_IPS.split(",") if ip.strip()]
formatted_ips = ",".join(ip_list)

print("\nIPs to add to Oracle Record:")
for ip in ip_list:
    print(f" - {ip}")

logging.info(f"Target Oracle Record ID: {AUTH_RECORD_ID} | IPs: {formatted_ips}")

# ---------------------------------
# Qualys API Call
# ---------------------------------
payload = {
    "action": "update",
    "id": AUTH_RECORD_ID,
    # Using 'add_ips' appends to the existing record. 
    "add_ips": formatted_ips 
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
        headers=headers,
        verify=False,  # Bypasses the corporate SSL/Proxy inspection issue
        timeout=30     # Prevents the script from hanging
    )

    print(f"\nStatus Code: {response.status_code}")
    logging.info(f"Status Code: {response.status_code}")

    if response.status_code == 200:
        print("\n✅ Oracle authentication record updated successfully!")
        logging.info("Oracle authentication record updated successfully.")
    else:
        print("\n❌ Failed to update Oracle authentication record.")
        logging.error(f"Failed API request. Status Code: {response.status_code}")
        
    # Attempt to parse the XML to give you a clean error message from Qualys
    try:
        root = ET.fromstring(response.text)
        return_node = root.find('.//RETURN') or root.find('.//SIMPLE_RETURN')
        if return_node is not None:
            print("API Message:")
            for child in return_node:
                print(f"  {child.tag}: {child.text}")
                logging.info(f"Qualys API Return: {child.tag} - {child.text}")
        else:
            # If Qualys returns an error structure instead of a return structure
            error_node = root.find('.//ERROR')
            if error_node is not None:
                print("API Error Details:")
                code = error_node.find('CODE')
                msg = error_node.find('MESSAGE')
                if code is not None and msg is not None:
                     print(f"  Code {code.text}: {msg.text}")
                     logging.error(f"Qualys API Error: Code {code.text} - {msg.text}")

    except ET.ParseError:
        print(f"\nRaw Response:\n{response.text}")
        logging.info(f"Raw Response: {response.text}")

except requests.exceptions.RequestException as e:
    print(f"\nNetwork/Request Error occurred: {str(e)}")
    logging.error(f"Request exception: {str(e)}")
except Exception as e:
    print(f"\nUnexpected error occurred: {str(e)}")
    logging.error(f"Script error: {str(e)}")
