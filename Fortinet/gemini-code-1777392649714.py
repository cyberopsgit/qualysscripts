import os
import sys
import logging
import traceback
import requests
from typing import List, Optional

# --- Configuration & Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Constants
QUALYS_GROUP_URL = "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"
QUALYS_AUTH_URL = "https://qualysapi.qualys.com/api/2.0/fo/auth/unix/"
SW_URL = "https://solarwinds.int.ally.com:17774/SolarWinds/InformationService/v3/Json/Query"

class QualysSync:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"X-Requested-With": "python-requests"})
        
        # Load credentials
        self.sw_auth = (os.getenv("SOLARWINDS_USERNAME"), os.getenv("SOLARWINDS_PASSWORD"))
        self.qualys_auth = (os.getenv("QUALYS_USER"), os.getenv("QUALYS_PASS"))
        self.group_id = os.getenv("QUALYS_GROUP_ID")
        self.auth_record_id = os.getenv("AUTH_RECORD_ID")
        
        self.verify_ssl = False # Set to True in production with proper certs

    def validate_env(self):
        """Ensure all required environment variables are present."""
        required = {
            "SW_USER": self.sw_auth[0], "SW_PASS": self.sw_auth[1],
            "Q_USER": self.qualys_auth[0], "Q_PASS": self.qualys_auth[1],
            "GROUP_ID": self.group_id
        }
        missing = [k for k, v in required.items() if not v]
        if missing:
            logger.error(f"Missing required ENV variables: {missing}")
            sys.exit(1)

    def fetch_solarwinds_ips(self) -> List[str]:
        """Fetch Fortinet IPs from SolarWinds Orion."""
        logger.info("Stage 1: Fetching IPs from SolarWinds...")
        payload = {"query": "SELECT IPAddress FROM Orion.Nodes WHERE Vendor LIKE '%Fortinet%'"}
        
        try:
            resp = self.session.post(SW_URL, json=payload, auth=self.sw_auth, verify=self.verify_ssl, timeout=30)
            resp.raise_for_status()
            ips = [row['IPAddress'] for row in resp.json().get('results', []) if row.get('IPAddress')]
            unique_ips = sorted(list(set(ips)))
            logger.info(f"Successfully fetched {len(unique_ips)} unique IPs.")
            return unique_ips
        except Exception as e:
            logger.error(f"Failed to fetch SolarWinds data: {e}")
            raise

    def update_qualys_asset_group(self, ips: List[str]):
        """Sync IPs to the specific Qualys Asset Group."""
        logger.info(f"Stage 2: Syncing IPs to Qualys Asset Group {self.group_id}...")
        data = {
            "action": "edit",
            "id": self.group_id,
            "set_ips": ",".join(ips)
        }
        try:
            # We skip the 'clear' step because 'set_ips' replaces the existing list
            resp = self.session.post(QUALYS_GROUP_URL, data=data, auth=self.qualys_auth, verify=self.verify_ssl, timeout=60)
            resp.raise_for_status()
            logger.info("Asset Group sync successful.")
        except Exception as e:
            logger.error(f"Failed to update Qualys Asset Group: {e}")
            raise

    def update_qualys_auth_record(self, ips: List[str]):
        """Update the Qualys Authentication Record if an ID is provided."""
        if not self.auth_record_id:
            logger.info("Skipping Stage 3: No AUTH_RECORD_ID provided.")
            return

        logger.info(f"Stage 3: Updating Qualys Auth Record {self.auth_record_id}...")
        data = {
            "action": "update",
            "ids": self.auth_record_id,
            "ips": ",".join(ips)
        }
        try:
            resp = self.session.post(QUALYS_AUTH_URL, data=data, auth=self.qualys_auth, verify=self.verify_ssl, timeout=120)
            resp.raise_for_status()
            logger.info("Auth Record update successful.")
        except Exception as e:
            logger.error(f"Failed to update Qualys Auth Record: {e}")
            raise

def main():
    sync = QualysSync()
    try:
        sync.validate_env()
        ips = sync.fetch_solarwinds_ips()
        
        if not ips:
            logger.warning("No IPs found in SolarWinds. Exiting to avoid clearing Qualys records.")
            return

        sync.update_qualys_asset_group(ips)
        sync.update_qualys_auth_record(ips)
        
        logger.info("Full synchronization completed successfully.")
    except Exception:
        logger.critical("Script failed during execution.")
        sys.exit(1)

if __name__ == "__main__":
    main()