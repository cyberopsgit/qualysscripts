#!/usr/bin/env python3

import os
import sys
import json
import ipaddress
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

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

# FortiManager may use a self-signed/internal certificate
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

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")


def log_raw(title, data):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n")
        f.write("=" * 80 + "\n")
        f.write(f"RAW API DATA - {title}\n")
        f.write("=" * 80 + "\n")

        try:
            f.write(json.dumps(data, indent=2, default=str))
        except Exception:
            f.write(str(data))

        f.write("\n")
        f.write("=" * 80 + "\n\n")


def api_call(url):
    payload = {
        "id": 1,
        "jsonrpc": "2.0",
        "method": "get",
        "params": [
            {
                "url": url
            }
        ]
    }

    log(f"API request: {url}")

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

    log(f"HTTP status: {response.status_code}")

    response.raise_for_status()

    result = response.json()

    # Save complete raw API response to log
    log_raw(url, result)

    # Check JSON-RPC result
    if "result" not in result:
        raise Exception(
            f"Unexpected API response - 'result' field missing"
        )

    api_result = result["result"]

    if isinstance(api_result, list):
        if not api_result:
            return []

        api_result = api_result[0]

    if not isinstance(api_result, dict):
        raise Exception(
            f"Unexpected API result format: {type(api_result)}"
        )

    # Check FortiManager API status
    status = api_result.get("status")

    if isinstance(status, dict):
        code = status.get("code")

        if code not in (0, "0", None):
            message = status.get("message", "Unknown API error")
            raise Exception(
                f"FortiManager API error {code}: {message}"
            )

    data = api_result.get("data", [])

    if data is None:
        return []

    return data


def get_ip(device):
    for field in (
        "ip",
        "ip_address",
        "mgmt_ip",
        "management_ip"
    ):
        value = device.get(field)

        if not value:
            continue

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
        print("SCRIPT FAILED - FMG_URL is missing")
        return 1

    if not API_KEY:
        print("SCRIPT FAILED - FMG_API_KEY is missing")
        return 1

    try:

        log("Script started")
        log(f"FortiManager: {FMG_URL}")
        log(f"IP output file: {IP_FILE}")
        log(f"Log output file: {LOG_FILE}")

        # ---------------------------------------------------------
        # Get ADOMs
        # ---------------------------------------------------------

        log("Getting ADOMs...")

        adoms = api_call("/dvmdb/adom")

        if isinstance(adoms, dict):
            adoms = [adoms]

        if not isinstance(adoms, list):
            raise Exception(
                f"Unexpected ADOM response format: {type(adoms)}"
            )

        log(f"ADOM records returned: {len(adoms)}")

        # ---------------------------------------------------------
        # Device collections
        # ---------------------------------------------------------

        fortigate = set()
        fortimanager = set()
        fortianalyzer = set()

        total_devices = 0

        for adom in adoms:

            if isinstance(adom, dict):
                adom_name = (
                    adom.get("name")
                    or adom.get("adom")
                    or adom.get("adom_name")
                )
            else:
                adom_name = str(adom)

            if not adom_name:
                log("Skipping ADOM with no name")
                continue

            log(f"Processing ADOM: {adom_name}")

            # URL encode ADOM name
            encoded_adom = quote(str(adom_name), safe="")

            devices = api_call(
                f"/dvmdb/adom/{encoded_adom}/device"
            )

            if isinstance(devices, dict):
                devices = [devices]

            if not isinstance(devices, list):
                raise Exception(
                    f"Unexpected device response format for ADOM "
                    f"{adom_name}: {type(devices)}"
                )

            log(
                f"Devices returned for {adom_name}: "
                f"{len(devices)}"
            )

            for device in devices:

                if not isinstance(device, dict):
                    log(
                        f"Skipping unexpected device record: "
                        f"{device}"
                    )
                    continue

                total_devices += 1

                name = (
                    device.get("name")
                    or device.get("hostname")
                    or device.get("serial")
                    or "UNKNOWN"
                )

                ip = get_ip(device)

                if not ip:
                    log(f"No management IP found: {name}")
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

        # ---------------------------------------------------------
        # Write IP file
        # ---------------------------------------------------------

        with open(IP_FILE, "w", encoding="utf-8") as f:

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

        # ---------------------------------------------------------
        # Results
        # ---------------------------------------------------------

        log(f"Total devices found: {total_devices}")
        log(f"FortiGate IPs: {len(fortigate)}")
        log(f"FortiManager IPs: {len(fortimanager)}")
        log(f"FortiAnalyzer IPs: {len(fortianalyzer)}")
        log(f"IP list written to: {IP_FILE}")

        # Do not call an empty API response a successful inventory
        if total_devices == 0:
            log("SCRIPT FAILED - No devices were returned by FortiManager")

            print("\n========================================")
            print("SCRIPT FAILED")
            print("========================================")
            print("No devices were returned by FortiManager")
            print(f"IP file : {IP_FILE}")
            print(f"Log file: {LOG_FILE}")

            return 1

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
