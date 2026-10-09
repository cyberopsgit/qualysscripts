#!/usr/bin/env python3

import os
import sys
import json
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

import urllib3

# FortiManager may use a self-signed/internal certificate
urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

load_dotenv()

FMG_URL = os.getenv("FMG_URL", "").rstrip("/")
API_KEY = os.getenv("FMG_API_KEY", "")

DATE = datetime.now().strftime("%Y%m%d")

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

IP_FILE = OUTPUT_DIR / f"fortinet_ip_{DATE}.txt"
LOG_FILE = OUTPUT_DIR / f"fortinet_inventory_{DATE}.log"


def log(message):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} - {message}"

    print(line)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


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

    # Save raw API response
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n")
        f.write("=" * 80 + "\n")
        f.write(f"RAW API RESPONSE: {url}\n")
        f.write("=" * 80 + "\n")
        f.write(json.dumps(result, indent=2, default=str))
        f.write("\n")
        f.write("=" * 80 + "\n\n")

    if "result" not in result:
        raise Exception(
            "Invalid FortiManager response: result field missing"
        )

    if not result["result"]:
        raise Exception(
            "Invalid FortiManager response: empty result"
        )

    api_result = result["result"][0]

    status = api_result.get("status", {})

    if status.get("code") not in (0, None):
        raise Exception(
            f"FortiManager API error: "
            f"{status.get('message', 'Unknown error')}"
        )

    return api_result.get("data", [])


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

    fields = (
        "platform",
        "platform_str",
        "type",
        "device_type",
        "devtype",
        "model",
        "description",
        "name",
        "hostname"
    )

    text = " ".join(
        str(device.get(field, "")).lower()
        for field in fields
    )

    if "fortianalyzer" in text or "forti analyzer" in text:
        return "FORTIANALYZER"

    if "fortimanager" in text or "forti manager" in text:
        return "FORTIMANAGER"

    if "fortigate" in text:
        return "FORTIGATE"

    # Common FortiGate model naming
    model = str(device.get("model", "")).lower()

    if model.startswith("fg"):
        return "FORTIGATE"

    return "UNKNOWN"


def get_device_name(device):

    return (
        device.get("name")
        or device.get("hostname")
        or device.get("device_name")
        or "UNKNOWN"
    )


def get_serial(device):

    return (
        device.get("serial")
        or device.get("sn")
        or device.get("serial_number")
        or "UNKNOWN"
    )


def get_model(device):

    return (
        device.get("model")
        or device.get("platform_str")
        or device.get("platform")
        or "UNKNOWN"
    )


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
        log(f"IP file: {IP_FILE}")
        log(f"Log file: {LOG_FILE}")

        fortigate = {}
        fortimanager = {}
        fortianalyzer = {}

        log("Getting managed devices...")

        devices = api_call("/dvmdb/device")

        if isinstance(devices, dict):
            devices = [devices]

        if not isinstance(devices, list):
            raise Exception(
                "Unexpected managed device response"
            )

        log(
            f"Managed device records returned: "
            f"{len(devices)}"
        )

        # ---------------------------------------------------------
        # Correlate every device
        # ---------------------------------------------------------

        for device in devices:

            if not isinstance(device, dict):
                continue

            name = get_device_name(device)
            serial = get_serial(device)
            model = get_model(device)
            ip = get_ip(device)
            dtype = get_device_type(device)

            log(
                f"DEVICE | "
                f"Type={dtype} | "
                f"Name={name} | "
                f"Serial={serial} | "
                f"Model={model} | "
                f"IP={ip or 'NOT FOUND'}"
            )

            if not ip:
                continue

            record = {
                "name": name,
                "serial": serial,
                "model": model,
                "ip": ip
            }

            if dtype == "FORTIANALYZER":
                fortianalyzer[ip] = record

            elif dtype == "FORTIMANAGER":
                fortimanager[ip] = record

            elif dtype == "FORTIGATE":
                fortigate[ip] = record

            else:
                log(
                    f"UNKNOWN DEVICE TYPE | "
                    f"Name={name} | "
                    f"Serial={serial} | "
                    f"Model={model} | "
                    f"IP={ip}"
                )

        # ---------------------------------------------------------
        # Add FortiManager itself
        # ---------------------------------------------------------

        try:

            fmg_host = (
                FMG_URL
                .split("//", 1)[1]
                .split("/", 1)[0]
                .split(":", 1)[0]
            )

            ipaddress.ip_address(fmg_host)

            if fmg_host not in fortimanager:

                fortimanager[fmg_host] = {
                    "name": "FortiManager",
                    "serial": "LOCAL",
                    "model": "FortiManager",
                    "ip": fmg_host
                }

                log(
                    f"DEVICE | "
                    f"Type=FORTIMANAGER | "
                    f"Name=FortiManager | "
                    f"Serial=LOCAL | "
                    f"Model=FortiManager | "
                    f"IP={fmg_host}"
                )

        except (ValueError, IndexError):
            pass

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
        # Summary
        # ---------------------------------------------------------

        log(f"FortiGate IPs: {len(fortigate)}")
        log(f"FortiManager IPs: {len(fortimanager)}")
        log(f"FortiAnalyzer IPs: {len(fortianalyzer)}")
        log(f"IP list written to: {IP_FILE}")

        if not fortigate and not fortimanager and not fortianalyzer:
            raise Exception(
                "No device IP addresses were found"
            )

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
