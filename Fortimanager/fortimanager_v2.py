#!/usr/bin/env python3
import os
import sys
import ipaddress
import subprocess
from datetime import datetime
from pathlib import Path

# Install dependencies if missing
try:
    import requests
    from dotenv import load_dotenv
except ImportError:
    subprocess.check_call([
        sys.executable, "-m", "pip", "install",
        "requests", "python-dotenv"
    ])
    import requests
    from dotenv import load_dotenv

# Suppress SSL warning because FortiManager uses an untrusted/self-signed certificate
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


load_dotenv()

FMG_URL = os.getenv("FMG_URL", "").rstrip("/")
API_KEY = os.getenv("FMG_API_KEY", "")

DATE = datetime.now().strftime("%Y%m%d")

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

IP_FILE = OUTPUT_DIR / f"fortinet_ip_{DATE}.txt"
LOG_FILE = OUTPUT_DIR / f"fortinet_inventory_{DATE}.log"


def log(message):
    message = f"{datetime.now():%Y-%m-%d %H:%M:%S} - {message}"
    print(message)

    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")


def api_call(url):
    payload = {
        "id": 1,
        "jsonrpc": "2.0",
        "method": "get",
        "params": [{"url": url}]
    }

    response = requests.post(
        f"{FMG_URL}/jsonrpc",
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        },
        json=payload,
        verify=False,
        timeout=60
    )

    response.raise_for_status()

    result = response.json()

    if "error" in result:
        raise Exception(result["error"])

    return result["result"][0].get("data", [])


def get_ip(device):
    for field in ("ip", "ip_address", "mgmt_ip", "management_ip"):
        value = device.get(field)

        try:
            ip = ipaddress.ip_address(str(value))
            if ip.version == 4:
                return str(ip)
        except ValueError:
            pass

    return None


def get_device_type(device):
    text = " ".join(
        str(device.get(field, "")).lower()
        for field in (
            "platform",
            "platform_str",
            "type",
            "device_type",
            "devtype",
            "model",
            "name",
            "hostname"
        )
    )

    if "fortianalyzer" in text or "forti analyzer" in text:
        return "FORTIANALYZER"

    if "fortimanager" in text or "forti manager" in text:
        return "FORTIMANAGER"

    return "FORTIGATE"


def main():

    if not FMG_URL:
        log("SCRIPT FAILED - FMG_URL is missing")
        return 1

    if not API_KEY:
        log("SCRIPT FAILED - FMG_API_KEY is missing")
        return 1

    try:
        log("Script started")
        log(f"FortiManager: {FMG_URL}")

        adoms = api_call("/dvmdb/adom")

        if isinstance(adoms, dict):
            adoms = [adoms]

        fortigate = set()
        fortimanager = set()
        fortianalyzer = set()

        total_devices = 0

        for adom in adoms:

            adom_name = adom.get("name") if isinstance(adom, dict) else adom

            if not adom_name:
                continue

            log(f"Processing ADOM: {adom_name}")

            devices = api_call(
                f"/dvmdb/adom/{adom_name}/device"
            )

            if isinstance(devices, dict):
                devices = [devices]

            for device in devices:

                total_devices += 1

                name = (
                    device.get("name")
                    or device.get("hostname")
                    or "UNKNOWN"
                )

                ip = get_ip(device)

                if not ip:
                    log(f"No IP found: {name}")
                    continue

                device_type = get_device_type(device)

                log(
                    f"{device_type}: "
                    f"{name} - {ip}"
                )

                if device_type == "FORTIANALYZER":
                    fortianalyzer.add(ip)

                elif device_type == "FORTIMANAGER":
                    fortimanager.add(ip)

                else:
                    fortigate.add(ip)

        # Write IP file
        with open(IP_FILE, "w") as f:

            f.write("========================================\n")
            f.write("FORTIGATE DEVICES\n")
            f.write("========================================\n\n")

            for ip in sorted(
                fortigate,
                key=lambda x: int(ipaddress.ip_address(x))
            ):
                f.write(ip + "\n")

            f.write("\n")
            f.write("========================================\n")
            f.write("FORTIMANAGER DEVICES\n")
            f.write("========================================\n\n")

            for ip in sorted(
                fortimanager,
                key=lambda x: int(ipaddress.ip_address(x))
            ):
                f.write(ip + "\n")

            f.write("\n")
            f.write("========================================\n")
            f.write("FORTIANALYZER DEVICES\n")
            f.write("========================================\n\n")

            for ip in sorted(
                fortianalyzer,
                key=lambda x: int(ipaddress.ip_address(x))
            ):
                f.write(ip + "\n")

        log(f"Total devices found: {total_devices}")
        log(f"FortiGate IPs: {len(fortigate)}")
        log(f"FortiManager IPs: {len(fortimanager)}")
        log(f"FortiAnalyzer IPs: {len(fortianalyzer)}")
        log(f"IP list written to: {IP_FILE}")

        log("SCRIPT COMPLETED SUCCESSFULLY")

        print("\n========================================")
        print("SCRIPT COMPLETED SUCCESSFULLY")
        print("========================================")
        print(f"IP file : {IP_FILE}")
        print(f"Log file: {LOG_FILE}")

        return 0

    except Exception as e:

        log(f"SCRIPT FAILED - {e}")

        print("\n========================================")
        print("SCRIPT FAILED")
        print("========================================")
        print(f"Error: {e}")
        print(f"Log file: {LOG_FILE}")

        return 1


if __name__ == "__main__":
    sys.exit(main())
