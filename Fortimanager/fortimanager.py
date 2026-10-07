#!/usr/bin/env python3

import importlib
import subprocess
import sys


# ============================================================
# INSTALL REQUIRED DEPENDENCIES
# ============================================================

REQUIRED_PACKAGES = {
    "requests": "requests",
    "dotenv": "python-dotenv",
}


def install_missing_dependencies():

    missing = []

    for module, package in REQUIRED_PACKAGES.items():

        try:
            importlib.import_module(module)

        except ImportError:
            missing.append(package)

    if not missing:
        return

    print(
        "Installing missing dependencies: "
        + ", ".join(missing)
    )

    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            *missing,
        ]
    )


install_missing_dependencies()


# ============================================================
# IMPORT DEPENDENCIES
# ============================================================

import ipaddress
import logging
import os
from datetime import datetime
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

FMG_URL = os.getenv(
    "FMG_URL",
    ""
).strip().rstrip("/")

FMG_API_KEY = os.getenv(
    "FMG_API_KEY",
    ""
).strip()

VERIFY_SSL = os.getenv(
    "VERIFY_SSL",
    "false"
).lower() in (
    "true",
    "1",
    "yes"
)

REQUEST_TIMEOUT = int(
    os.getenv(
        "REQUEST_TIMEOUT",
        "60"
    )
)


# ============================================================
# OUTPUT
# ============================================================

RUN_DATE = datetime.now().strftime(
    "%Y%m%d"
)

OUTPUT_DIR = Path("output")

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

IP_FILE = (
    OUTPUT_DIR /
    f"fortinet_ip_{RUN_DATE}.txt"
)

LOG_FILE = (
    OUTPUT_DIR /
    f"fortinet_inventory_{RUN_DATE}.log"
)


# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger(
    "fortinet_inventory"
)

logger.setLevel(
    logging.INFO
)

logger.handlers.clear()

formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s"
)

file_handler = logging.FileHandler(
    LOG_FILE,
    encoding="utf-8"
)

file_handler.setFormatter(
    formatter
)

console_handler = logging.StreamHandler(
    sys.stdout
)

console_handler.setFormatter(
    formatter
)

logger.addHandler(
    file_handler
)

logger.addHandler(
    console_handler
)


if not VERIFY_SSL:

    urllib3.disable_warnings(
        urllib3.exceptions.InsecureRequestWarning
    )


# ============================================================
# FORTIMANAGER CLIENT
# ============================================================

class FortiManagerClient:

    def __init__(
        self,
        url,
        api_key
    ):

        self.endpoint = (
            f"{url}/jsonrpc"
        )

        self.session = requests.Session()

        self.session.headers.update(
            {
                "Authorization":
                    f"Bearer {api_key}",

                "Content-Type":
                    "application/json",

                "Accept":
                    "application/json"
            }
        )

        self.session.verify = VERIFY_SSL

        self.request_id = 1

    def call(
        self,
        method,
        url
    ):

        payload = {
            "id":
                self.request_id,

            "jsonrpc":
                "2.0",

            "method":
                method,

            "params": [
                {
                    "url":
                        url
                }
            ]
        }

        self.request_id += 1

        response = self.session.post(
            self.endpoint,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        result = response.json()

        if "error" in result:

            raise RuntimeError(
                f"JSON-RPC error: "
                f"{result['error']}"
            )

        results = result.get(
            "result",
            []
        )

        if not results:

            return []

        result_data = results[0]

        status = result_data.get(
            "status",
            {}
        )

        if isinstance(
            status,
            dict
        ):

            code = status.get(
                "code",
                0
            )

            if code not in (
                0,
                None
            ):

                raise RuntimeError(
                    f"FortiManager API error: "
                    f"{status}"
                )

        return result_data.get(
            "data",
            []
        )


# ============================================================
# GET ADOMS
# ============================================================

def get_adoms(
    client
):

    logger.info(
        "Getting ADOMs..."
    )

    data = client.call(
        "get",
        "/dvmdb/adom"
    )

    if isinstance(
        data,
        dict
    ):

        data = [data]

    adoms = []

    for item in data:

        if isinstance(
            item,
            dict
        ):

            name = (
                item.get("name")
                or item.get("adom")
                or item.get("adom_name")
            )

        elif isinstance(
            item,
            str
        ):

            name = item

        else:

            name = None

        if name:

            adoms.append(
                name
            )

    return sorted(
        set(adoms)
    )


# ============================================================
# GET MANAGED DEVICES
# ============================================================

def get_devices(
    client,
    adom
):

    return client.call(
        "get",
        f"/dvmdb/adom/{adom}/device"
    )


# ============================================================
# IP VALIDATION
# ============================================================

def get_ipv4(
    value
):

    if not value:
        return None

    try:

        address = ipaddress.ip_address(
            str(value).strip()
        )

        if address.version == 4:

            return str(address)

    except ValueError:

        pass

    return None


# ============================================================
# DEVICE IP
# ============================================================

def get_device_ip(
    device
):

    fields = [
        "ip",
        "ip_address",
        "mgmt_ip",
        "management_ip",
        "management-ip"
    ]

    for field in fields:

        ip = get_ipv4(
            device.get(field)
        )

        if ip:
            return ip

    return None


# ============================================================
# DEVICE TYPE
# ============================================================

def get_device_type(
    device
):

    values = []

    fields = [
        "platform",
        "platform_str",
        "type",
        "devtype",
        "device_type",
        "os_type",
        "name",
        "hostname",
        "description"
    ]

    for field in fields:

        value = device.get(
            field
        )

        if value:

            values.append(
                str(value).lower()
            )

    text = " ".join(
        values
    )

    # FortiAnalyzer
    if (
        "fortianalyzer" in text
        or "forti-analyzer" in text
        or "forti analyzer" in text
        or "faz" in text.split()
    ):

        return "FORTIANALYZER"

    # FortiManager
    if (
        "fortimanager" in text
        or "forti-manager" in text
        or "forti manager" in text
        or "fmg" in text.split()
    ):

        return "FORTIMANAGER"

    # FortiGate
    if (
        "fortigate" in text
        or "forti-gate" in text
        or "forti gate" in text
        or "fg" in text.split()
    ):

        return "FORTIGATE"

    # FortiGate models often contain
    # FortiGate in platform_str, but if
    # that field is absent, inspect model.
    model = str(
        device.get(
            "model",
            ""
        )
    ).lower()

    if (
        "fortigate" in model
        or model.startswith("fg")
    ):

        return "FORTIGATE"

    return "FORTIGATE"


# ============================================================
# DEVICE NAME
# ============================================================

def get_device_name(
    device
):

    return (
        device.get("name")
        or device.get("hostname")
        or device.get("device_name")
        or device.get("desc")
        or "UNKNOWN"
    )


# ============================================================
# COLLECT
# ============================================================

def collect(
    client
):

    fortigate_ips = set()
    fortimanager_ips = set()
    fortianalyzer_ips = set()

    total_devices = 0

    adoms = get_adoms(
        client
    )

    logger.info(
        "ADOMs found: %d",
        len(adoms)
    )

    if not adoms:

        raise RuntimeError(
            "No ADOMs found."
        )

    for adom in adoms:

        logger.info(
            "Processing ADOM: %s",
            adom
        )

        devices = get_devices(
            client,
            adom
        )

        logger.info(
            "Devices found in %s: %d",
            adom,
            len(devices)
        )

        for device in devices:

            if not isinstance(
                device,
                dict
            ):

                continue

            total_devices += 1

            name = get_device_name(
                device
            )

            device_type = get_device_type(
                device
            )

            ip = get_device_ip(
                device
            )

            logger.info(
                "Device: %s | Type: %s | IP: %s",
                name,
                device_type,
                ip or "NOT FOUND"
            )

            if not ip:
                continue

            if device_type == "FORTIGATE":

                fortigate_ips.add(
                    ip
                )

            elif device_type == "FORTIMANAGER":

                fortimanager_ips.add(
                    ip
                )

            elif device_type == "FORTIANALYZER":

                fortianalyzer_ips.add(
                    ip
                )

    logger.info(
        "Total devices: %d",
        total_devices
    )

    logger.info(
        "FortiGate IPs: %d",
        len(fortigate_ips)
    )

    logger.info(
        "FortiManager IPs: %d",
        len(fortimanager_ips)
    )

    logger.info(
        "FortiAnalyzer IPs: %d",
        len(fortianalyzer_ips)
    )

    return (
        fortigate_ips,
        fortimanager_ips,
        fortianalyzer_ips
    )


# ============================================================
# SORT IPs
# ============================================================

def sort_ips(
    ips
):

    return sorted(
        ips,
        key=lambda ip:
            int(
                ipaddress.ip_address(
                    ip
                )
            )
    )


# ============================================================
# WRITE IP FILE
# ============================================================

def write_ip_file(
    fortigate_ips,
    fortimanager_ips,
    fortianalyzer_ips
):

    with IP_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "========================================\n"
        )

        file.write(
            "FORTIGATE DEVICES\n"
        )

        file.write(
            "========================================\n\n"
        )

        for ip in sort_ips(
            fortigate_ips
        ):

            file.write(
                f"{ip}\n"
            )

        file.write(
            "\n\n"
        )

        file.write(
            "========================================\n"
        )

        file.write(
            "FORTIMANAGER DEVICES\n"
        )

        file.write(
            "========================================\n\n"
        )

        for ip in sort_ips(
            fortimanager_ips
        ):

            file.write(
                f"{ip}\n"
            )

        file.write(
            "\n\n"
        )

        file.write(
            "========================================\n"
        )

        file.write(
            "FORTIANALYZER DEVICES\n"
        )

        file.write(
            "========================================\n\n"
        )

        for ip in sort_ips(
            fortianalyzer_ips
        ):

            file.write(
                f"{ip}\n"
            )


# ============================================================
# SUCCESS
# ============================================================

def script_success(
    fortigate_ips,
    fortimanager_ips,
    fortianalyzer_ips
):

    message = (
        "SCRIPT COMPLETED SUCCESSFULLY"
    )

    logger.info(
        message
    )

    logger.info(
        "FortiGate IPs: %d",
        len(fortigate_ips)
    )

    logger.info(
        "FortiManager IPs: %d",
        len(fortimanager_ips)
    )

    logger.info(
        "FortiAnalyzer IPs: %d",
        len(fortianalyzer_ips)
    )

    logger.info(
        "IP file: %s",
        IP_FILE
    )

    print()
    print(
        "=" * 60
    )
    print(
        message
    )
    print(
        "=" * 60
    )
    print(
        f"IP file : {IP_FILE}"
    )
    print(
        f"Log file: {LOG_FILE}"
    )

    return 0


# ============================================================
# FAILURE
# ============================================================

def script_failed(
    error
):

    logger.error(
        "SCRIPT FAILED"
    )

    logger.error(
        "Error: %s",
        error
    )

    print()
    print(
        "=" * 60
    )
    print(
        "SCRIPT FAILED"
    )
    print(
        "=" * 60
    )
    print(
        f"Error: {error}"
    )
    print(
        f"Log file: {LOG_FILE}"
    )

    return 1


# ============================================================
# MAIN
# ============================================================

def main():

    logger.info(
        "Fortinet inventory script started"
    )

    if not FMG_URL:

        return script_failed(
            "FMG_URL is missing from .env"
        )

    if not FMG_API_KEY:

        return script_failed(
            "FMG_API_KEY is missing from .env"
        )

    try:

        logger.info(
            "Connecting to FortiManager"
        )

        client = FortiManagerClient(
            FMG_URL,
            FMG_API_KEY
        )

        (
            fortigate_ips,
            fortimanager_ips,
            fortianalyzer_ips
        ) = collect(
            client
        )

        write_ip_file(
            fortigate_ips,
            fortimanager_ips,
            fortianalyzer_ips
        )

        return script_success(
            fortigate_ips,
            fortimanager_ips,
            fortianalyzer_ips
        )

    except requests.exceptions.RequestException as exc:

        return script_failed(
            f"FortiManager connection/API error: {exc}"
        )

    except Exception as exc:

        logger.exception(
            "Unexpected error"
        )

        return script_failed(
            str(exc)
        )


if __name__ == "__main__":

    sys.exit(
        main()
    )
