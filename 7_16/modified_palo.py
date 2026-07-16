import os
import sys
import requests
from datetime import datetime
from panos.panorama import Panorama
from panos.device import SystemSettings
from dotenv import load_dotenv
import logging
import urllib3
import traceback

# load .env file
load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# logging setup
date_str = datetime.now().strftime("%Y%m%d")
log_filename = f"log_{date_str}.log"

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
for h in list(logger.handlers):
    logger.removeHandler(h)

fh = logging.FileHandler(log_filename, encoding="utf-8", mode="a")
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
logger.addHandler(fh)

ch = logging.StreamHandler(sys.__stdout__)
ch.setLevel(logging.CRITICAL)
logger.addHandler(ch)

ORIGINAL_STDOUT = sys.__stdout__

class LoggerWriter:
    def __init__(self, level_func):
        self.level_func = level_func
    def write(self, message):
        message = message.rstrip()
        if message:
            self.level_func(message)
    def flush(self):
        pass

sys.stdout = LoggerWriter(logger.debug)
sys.stderr = LoggerWriter(logger.error)

logger.info(f"Logging initialized. Log file: {os.path.abspath(log_filename)}")

# helper functions
def stage_start(name):
    print("\n" + "="*70)
    print(f"[Stage] {name} — Started")
    print("="*70)
    logger.info(f"--- [Stage] {name} — Started ---")

def stage_fail(name, err):
    print(f"❌ [Stage: {name}] Failed — {err}")
    logger.error(f"Stage {name} Failed: {err}")
    logger.error(traceback.format_exc())
    print("-"*70)

# environment variables
PALO_IP = os.getenv("PALO_IP")
PALO_API_KEY = os.getenv("PALO_API_KEY")

LAB_IP = os.getenv("LAB_IP")
LAB_API_KEY = os.getenv("LAB_API_KEY")

PCI1_HOST = os.getenv("PCI1_HOST")
PCI1_API_KEY = os.getenv("PCI1_API_KEY")

PCI2_HOST = os.getenv("PCI2_HOST")
PCI2_API_KEY = os.getenv("PCI2_API_KEY")

required = {
    "PALO_IP": PALO_IP,
    "PALO_API_KEY": PALO_API_KEY,
    "LAB_IP": LAB_IP,
    "LAB_API_KEY": LAB_API_KEY,
    "PCI1_HOST": PCI1_HOST,
    "PCI1_API_KEY": PCI1_API_KEY,
    "PCI2_HOST": PCI2_HOST,
    "PCI2_API_KEY": PCI2_API_KEY
}

missing = [k for k, v in required.items() if not v]
if missing:
    logger.critical(f"Missing environment variables: {', '.join(missing)}")
    print("Script Execution failed, please check the log file for details", file=ORIGINAL_STDOUT)
    sys.exit(2)

# Global trackers for Panorama Environments
env_summary = {
    "Prod Panorama": {"host": PALO_IP, "status": "Pending", "ips_fetched": 0, "error": None},
    "Lab Panorama": {"host": LAB_IP, "status": "Pending", "ips_fetched": 0, "error": None},
    "PCI-1 Panorama": {"host": PCI1_HOST, "status": "Pending", "ips_fetched": 0, "error": None},
    "PCI-2 Panorama": {"host": PCI2_HOST, "status": "Pending", "ips_fetched": 0, "error": None}
}
firewall_warnings = []  # Tracks individual firewalls that had missing data

# ==========================================
# Stage 1 - fetch from prod
# ==========================================
stage_name = "Fetch IPs from Prod Palo Alto"
stage_start(stage_name)
prod_ips = set()
try:
    pano = Panorama(PALO_IP, api_key=PALO_API_KEY)
    devices = pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    print(f"[+] Production Panorama devices count: {len(devices)}")
    logger.info(f"Found {len(devices)} devices in Production Panorama.")
    
    for dev in devices:
        hostname = getattr(dev, "hostname", None) or getattr(dev, "name", "Unknown_Hostname")
        serial = getattr(dev, "serial", "Unknown_Serial")
        version = getattr(dev, "version", getattr(dev, "sw_version", "Unknown_Version"))
        
        try:
            ss = dev.find("", SystemSettings)
            ip = getattr(ss, "ip_address", None) if ss else None
            
            if not ip:
                ip = getattr(dev, "ip-address", getattr(dev, "mgmt_ip", None))

            if ip:
                prod_ips.add(ip)
                print(f"{hostname},{serial},{version},{ip}")
                logger.debug(f"Success: {hostname},{serial},{version},{ip}")
            else:
                firewall_warnings.append(f"[Prod] Hostname: {hostname} | Reason: No IP address returned")
        except Exception as e:
            firewall_warnings.append(f"[Prod] Hostname: {hostname} | Error: {str(e)}")
            continue
            
    env_summary["Prod Panorama"]["status"] = "SUCCESS"
    env_summary["Prod Panorama"]["ips_fetched"] = len(prod_ips)
    logger.info("✅ [Stage: %s] Completed with %d IPs fetched", stage_name, len(prod_ips))
except Exception as e:
    env_summary["Prod Panorama"]["status"] = "FAILED"
    env_summary["Prod Panorama"]["error"] = str(e)
    stage_fail(stage_name, f"Could not connect to Prod Panorama at {PALO_IP}. Reason: {e}")


# ==========================================
# Stage 2 - fetch from lab
# ==========================================
stage_name = "Fetch IPs from Lab Palo Alto"
stage_start(stage_name)
lab_ips = set()
try:
    lab_pano = Panorama(LAB_IP, api_key=LAB_API_KEY)
    lab_devices = lab_pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    print(f"[+] Lab Panorama devices count: {len(lab_devices)}")
    logger.info(f"Found {len(lab_devices)} devices in Lab Panorama.")
    
    for dev in lab_devices:
        hostname = getattr(dev, "hostname", None) or getattr(dev, "name", "Unknown_Hostname")
        serial = getattr(dev, "serial", "Unknown_Serial")
        version = getattr(dev, "version", getattr(dev, "sw_version", "Unknown_Version"))
        
        try:
            ss = dev.find("", SystemSettings)
            ip = getattr(ss, "ip_address", None) if ss else None
            
            if not ip:
                ip = getattr(dev, "ip-address", getattr(dev, "mgmt_ip", None))

            if ip:
                lab_ips.add(ip)
                print(f"{hostname},{serial},{version},{ip}")
                logger.debug(f"Success: {hostname},{serial},{version},{ip}")
            else:
                firewall_warnings.append(f"[Lab] Hostname: {hostname} | Reason: No IP address returned")
        except Exception as e:
            firewall_warnings.append(f"[Lab] Hostname: {hostname} | Error: {str(e)}")
            continue
            
    env_summary["Lab Panorama"]["status"] = "SUCCESS"
    env_summary["Lab Panorama"]["ips_fetched"] = len(lab_ips)
    logger.info("✅ [Stage: %s] Completed with %d IPs fetched", stage_name, len(lab_ips))
except Exception as e:
    env_summary["Lab Panorama"]["status"] = "FAILED"
    env_summary["Lab Panorama"]["error"] = str(e)
    stage_fail(stage_name, f"Could not connect to Lab Panorama at {LAB_IP}. Reason: {e}")


# ==========================================
# Stage 3 - fetch from PCI 1
# ==========================================
stage_name = "Fetch IPs from PCI 1 Palo Alto"
stage_start(stage_name)
pci1_ips = set()
try:
    pci1_pano = Panorama(PCI1_HOST, api_key=PCI1_API_KEY)
    pci1_devices = pci1_pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    print(f"[+] PCI 1 Panorama devices count: {len(pci1_devices)}")
    logger.info(f"Found {len(pci1_devices)} devices in PCI 1 Panorama.")
    
    for dev in pci1_devices:
        hostname = getattr(dev, "hostname", None) or getattr(dev, "name", "Unknown_Hostname")
        serial = getattr(dev, "serial", "Unknown_Serial")
        version = getattr(dev, "version", getattr(dev, "sw_version", "Unknown_Version"))
        
        try:
            ss = dev.find("", SystemSettings)
            ip = getattr(ss, "ip_address", None) if ss else None
            
            if not ip:
                ip = getattr(dev, "ip-address", getattr(dev, "mgmt_ip", None))

            if ip:
                pci1_ips.add(ip)
                print(f"{hostname},{serial},{version},{ip}")
                logger.debug(f"Success: {hostname},{serial},{version},{ip}")
            else:
                firewall_warnings.append(f"[PCI-1] Hostname: {hostname} | Reason: No IP address returned")
        except Exception as e:
            firewall_warnings.append(f"[PCI-1] Hostname: {hostname} | Error: {str(e)}")
            continue
            
    env_summary["PCI-1 Panorama"]["status"] = "SUCCESS"
    env_summary["PCI-1 Panorama"]["ips_fetched"] = len(pci1_ips)
    logger.info("✅ [Stage: %s] Completed with %d IPs fetched", stage_name, len(pci1_ips))
except Exception as e:
    env_summary["PCI-1 Panorama"]["status"] = "FAILED"
    env_summary["PCI-1 Panorama"]["error"] = str(e)
    stage_fail(stage_name, f"Could not connect to PCI 1 Panorama at {PCI1_HOST}. Reason: {e}")


# ==========================================
# Stage 4 - fetch from PCI 2
# ==========================================
stage_name = "Fetch IPs from PCI 2 Palo Alto"
stage_start(stage_name)
pci2_ips = set()
try:
    pci2_pano = Panorama(PCI2_HOST, api_key=PCI2_API_KEY)
    pci2_devices = pci2_pano.refresh_devices(expand_vsys=False, include_device_groups=False)
    print(f"[+] PCI 2 Panorama devices count: {len(pci2_devices)}")
    logger.info(f"Found {len(pci2_devices)} devices in PCI 2 Panorama.")
    
    for dev in pci2_devices:
        hostname = getattr(dev, "hostname", None) or getattr(dev, "name", "Unknown_Hostname")
        serial = getattr(dev, "serial", "Unknown_Serial")
        version = getattr(dev, "version", getattr(dev, "sw_version", "Unknown_Version"))
        
        try:
            ss = dev.find("", SystemSettings)
            ip = getattr(ss, "ip_address", None) if ss else None
            
            if not ip:
                ip = getattr(dev, "ip-address", getattr(dev, "mgmt_ip", None))

            if ip:
                pci2_ips.add(ip)
                print(f"{hostname},{serial},{version},{ip}")
                logger.debug(f"Success: {hostname},{serial},{version},{ip}")
            else:
                firewall_warnings.append(f"[PCI-2] Hostname: {hostname} | Reason: No IP address returned")
        except Exception as e:
            firewall_warnings.append(f"[PCI-2] Hostname: {hostname} | Error: {str(e)}")
            continue
            
    env_summary["PCI-2 Panorama"]["status"] = "SUCCESS"
    env_summary["PCI-2 Panorama"]["ips_fetched"] = len(pci2_ips)
    logger.info("✅ [Stage: %s] Completed with %d IPs fetched", stage_name, len(pci2_ips))
except Exception as e:
    env_summary["PCI-2 Panorama"]["status"] = "FAILED"
    env_summary["PCI-2 Panorama"]["error"] = str(e)
    stage_fail(stage_name, f"Could not connect to PCI 2 Panorama at {PCI2_HOST}. Reason: {e}")


# ==========================================
# Stage 5 - combine
# ==========================================
stage_name = "Combine All IP Addresses"
stage_start(stage_name)
combined_ips = sorted(set(prod_ips) | set(lab_ips) | set(pci1_ips) | set(pci2_ips))
total_combined_fetched = len(combined_ips)
print(f"[INFO] Combined unique IP count: {total_combined_fetched}")
logger.info("Final Combined IP List:")
for ip in combined_ips:
    logger.info(f" - {ip}")


# ==========================================
# FINAL SUMMARY REPORT
# ==========================================
print("\n" + "="*75)
print(" FINAL EXECUTION SUMMARY ")
print("="*75)
print("Panorama Environments Status:")

logger.info("=== FINAL EXECUTION SUMMARY ===")
logger.info("Panorama Environments Status:")

all_failed = True
for env, data in env_summary.items():
    if data['status'] == "SUCCESS":
        all_failed = False
        msg = f" - {env} ({data['host']}): SUCCESS | IPs Fetched: {data['ips_fetched']}"
        print(msg)
        logger.info(msg)
    else:
        msg = f" - {env} ({data['host']}): FAILED  | Reason: {data['error']}"
        print(msg)
        logger.error(msg)

print("-" * 75)
print(f"Total Unique IPs Fetched Overall: {total_combined_fetched}")
logger.info(f"Total Unique IPs Fetched Overall: {total_combined_fetched}")

# Print warnings for individual firewalls that connected but had missing data
if firewall_warnings:
    print("\n[Firewall Fetch Warnings - Missing IPs/Data]")
    logger.warning("[Firewall Fetch Warnings - Missing IPs/Data]")
    for warn in firewall_warnings:
        print(f" * {warn}")
        logger.warning(warn)

print("="*75 + "\n")

# Determine exit status
if all_failed:
    print("Script Failed Completely (0 Environments Connected). Check log for details.", file=ORIGINAL_STDOUT)
    sys.exit(5)
elif any(data['status'] == "FAILED" for data in env_summary.values()):
    print("Script Executed with Partial Success (Some environments failed). Check log for details.", file=ORIGINAL_STDOUT)
    sys.exit(1)
else:
    print("Script Executed Successfully across all environments. Check log for details.", file=ORIGINAL_STDOUT)
    sys.exit(0)
