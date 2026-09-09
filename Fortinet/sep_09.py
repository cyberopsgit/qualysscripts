import os
import sys
import subprocess
import csv
import xml.etree.ElementTree as ET

# ---------------------------------------------------------
# Auto Install Required Packages
# ---------------------------------------------------------
required_packages = ["requests", "urllib3", "python-dotenv"]

for package in required_packages:
    try:
        import_name = "dotenv" if package == "python-dotenv" else package
        __import__(import_name)
    except ImportError:
        print(f"[*] Installing missing package: {package}...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", package],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

# ---------------------------------------------------------
# Imports
# ---------------------------------------------------------
import requests
import logging
import traceback
import datetime
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

# ---------------------------------------------------------
# Logging
# ---------------------------------------------------------
date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = f"sync_fortinet_qualys_{date_str}.log"

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler(log_filename, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
logger.addHandler(file_handler)

ORIGINAL_STDOUT = sys.stdout


def stage_start(name):
    msg = f"\n{'=' * 70}\n[Stage] {name} ⏳ Started\n{'=' * 70}"
    print(msg)
    logger.info(f"--- [Stage Started] {name} ---")


def stage_fail(name, err):
    msg = f"❌ [Stage: {name}] Failed 🚨 {err}"
    print(msg)
    print("-" * 70)
    logger.error(msg)
    logger.error(traceback.format_exc())


logger.info(
    f"Script started. Log file created: {os.path.abspath(log_filename)}"
)

# ---------------------------------------------------------
# ORIGINAL URLs - KEEPING YOUR ORIGINAL VALUES
# ---------------------------------------------------------
username = os.getenv("SOLARWINDS_USERNAME")
password = os.getenv("SOLARWINDS_PASSWORD")

solarwinds_url = (
    "https://solarwinds.int.ally.com:17774/"
    "SolarWinds/InformationService/v3/Json/Query"
)

qualys_user = os.getenv("QUALYS_USER")
qualys_pass = os.getenv("QUALYS_PASS")
qualys_group_id = os.getenv("QUALYS_GROUP_ID")

qualys_url = (
    "https://qualysapi.qualys.com/api/2.0/fo/asset/group/"
)

AUTH_RECORD_ID = os.getenv("AUTH_RECORD_ID")

QUALYS_AUTH_UPDATE_URL = (
    "https://qualysapi.qualys.com/api/2.0/fo/auth/unix/"
)

# ---------------------------------------------------------
# Files Configuration
# ---------------------------------------------------------
CMDB_CSV_FILE = os.getenv(
    "CMDB_CSV_FILE",
    "fortinet_cmdb_ips.csv"
)

TAG_MAPPING_CSV = os.getenv(
    "TAG_MAPPING_CSV",
    "tag_assignment_inventory.csv"
)

# ---------------------------------------------------------
# Asset Group Control
# true  = update Asset Group
# false = skip Asset Group
# ---------------------------------------------------------
UPDATE_QUALYS_ASSET_GROUP = (
    os.getenv(
        "UPDATE_QUALYS_ASSET_GROUP",
        "false"
    ).strip().lower() == "true"
)

# ---------------------------------------------------------
# Treat placeholder Auth Record ID as unconfigured
# ---------------------------------------------------------
if AUTH_RECORD_ID:
    if AUTH_RECORD_ID.strip().upper() in (
        "YOUR_AUTH_RECORD_ID",
        "YOUR_AUTHENTICATION_RECORD_ID",
    ):
        AUTH_RECORD_ID = ""

# ---------------------------------------------------------
# Required Environment Variables
# ---------------------------------------------------------
required = {
    "QUALYS_USER": qualys_user,
    "QUALYS_PASS": qualys_pass,
    "SOLARWINDS_USERNAME": username,
    "SOLARWINDS_PASSWORD": password,
}

if UPDATE_QUALYS_ASSET_GROUP:
    required["QUALYS_GROUP_ID"] = qualys_group_id

missing = [k for k, v in required.items() if not v]

if missing:
    err_msg = (
        f"Missing environment variables: "
        f"{', '.join(missing)}"
    )

    logger.critical(err_msg)

    print(
        "Script Execution failed, please check the log file for details.",
        file=ORIGINAL_STDOUT
    )

    sys.exit(2)

# ---------------------------------------------------------
# Global Data
# ---------------------------------------------------------
overall_ok = True

solarwinds_ips = []
cmdb_ips = []
merged_ips = []

ip_to_tag_mapping = {}
tag_to_ips_mapping = {}

unmapped_ips = []

# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------


def is_valid_ip(ip):
    """Basic IPv4 validation."""
    parts = str(ip).split(".")

    if len(parts) != 4:
        return False

    try:
        return all(
            0 <= int(part) <= 255
            for part in parts
        )
    except ValueError:
        return False


def read_cmdb_csv():
    """Read CMDB IPs from CSV file."""

    try:
        if not os.path.exists(CMDB_CSV_FILE):
            print(
                f"[⚠️] CMDB CSV file not found: "
                f"{CMDB_CSV_FILE}"
            )

            logger.warning(
                f"CMDB CSV file not found: "
                f"{CMDB_CSV_FILE}"
            )

            return []

        with open(
            CMDB_CSV_FILE,
            "r",
            newline="",
            encoding="utf-8-sig"
        ) as f:

            reader = csv.DictReader(f)

            if not reader.fieldnames:
                logger.error(
                    "CMDB CSV has no header."
                )
                return []

            if "IP Address" not in reader.fieldnames:
                logger.error(
                    "CMDB CSV must contain an "
                    "'IP Address' column. "
                    f"Found: {reader.fieldnames}"
                )
                return []

            ips = []

            for idx, row in enumerate(reader, start=2):

                ip = (row.get("IP Address") or "").strip()

                if ip and is_valid_ip(ip):
                    ips.append(ip)

                elif ip:
                    logger.warning(
                        f"Skipped invalid CMDB IP "
                        f"on row {idx}: {ip}"
                    )

            return sorted(set(ips))

    except Exception as e:

        print(
            f"[X] Error reading CMDB CSV: {e}"
        )

        logger.error(
            f"Error reading CMDB CSV: {e}"
        )

        return []


def read_tag_mapping_csv():
    """Read IP -> Qualys Tag ID mapping from CSV."""

    try:
        if not os.path.exists(TAG_MAPPING_CSV):

            print(
                f"[⚠️] Tag mapping CSV not found: "
                f"{TAG_MAPPING_CSV}"
            )

            logger.warning(
                f"Tag mapping CSV not found: "
                f"{TAG_MAPPING_CSV}"
            )

            return {}

        with open(
            TAG_MAPPING_CSV,
            "r",
            newline="",
            encoding="utf-8-sig"
        ) as f:

            reader = csv.DictReader(f)

            if not reader.fieldnames:
                logger.error(
                    "Tag mapping CSV has no header."
                )
                return {}

            required_columns = {
                "IP Address",
                "Qualys Tag ID"
            }

            missing_columns = (
                required_columns
                - set(reader.fieldnames)
            )

            if missing_columns:

                logger.error(
                    "Tag mapping CSV missing "
                    "column(s): "
                    f"{', '.join(sorted(missing_columns))}"
                )

                return {}

            mapping = {}

            for idx, row in enumerate(reader, start=2):

                ip = (
                    row.get("IP Address") or ""
                ).strip()

                tag_id = (
                    row.get("Qualys Tag ID") or ""
                ).strip()

                if ip and tag_id and is_valid_ip(ip):

                    mapping[ip] = tag_id

                elif ip:

                    logger.warning(
                        f"Skipped invalid tag mapping "
                        f"on row {idx}: "
                        f"{ip} -> {tag_id}"
                    )

            return mapping

    except Exception as e:

        print(
            f"[X] Error reading tag mapping CSV: {e}"
        )

        logger.error(
            f"Error reading tag mapping CSV: {e}"
        )

        return {}


# ---------------------------------------------------------
# NEW QUALYS TAG PROCESS
#
# The old implementation tried to update the Tag itself
# using ruleText containing a list of IPs.
#
# Instead:
#   1. Search Qualys Host Asset by IP address.
#   2. Get the Host Asset ID.
#   3. Add the specified static Tag ID to that Host Asset.
# ---------------------------------------------------------


def get_qualys_host_asset_id(ip):
    """
    Search Qualys Host Asset by IP address and return
    the matching Host Asset ID.
    """

    search_url = (
        "https://qualysapi.qualys.com/"
        "qps/rest/2.0/search/am/hostasset"
    )

    xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<ServiceRequest>
    <filters>
        <Criteria field="address"
                   operator="EQUALS">{ip}</Criteria>
    </filters>
</ServiceRequest>
"""

    try:

        response = requests.post(
            search_url,
            data=xml_payload.encode("utf-8"),
            auth=(qualys_user, qualys_pass),
            verify=False,
            headers={
                "Content-Type": "text/xml",
                "Accept": "text/xml",
                "X-Requested-With": "python-requests",
            },
            timeout=120,
        )

        if response.status_code != 200:

            logger.error(
                f"Qualys Host Asset search failed "
                f"for IP {ip}: "
                f"HTTP {response.status_code}"
            )

            logger.error(
                f"Response Headers: "
                f"{dict(response.headers)}"
            )

            logger.error(
                f"Response Body: "
                f"{response.text}"
            )

            return None

        try:
            root = ET.fromstring(response.text)

        except ET.ParseError as e:

            logger.error(
                f"Unable to parse Qualys search response "
                f"for IP {ip}: {e}"
            )

            logger.error(
                f"Raw Response: {response.text}"
            )

            return None

        # Find HostAsset element regardless of XML namespace.
        host_assets = []

        for element in root.iter():

            if element.tag.split("}")[-1] == "HostAsset":
                host_assets.append(element)

        if not host_assets:

            logger.warning(
                f"No Qualys Host Asset found for IP {ip}"
            )

            return None

        # Use the first exact search result.
        host_asset = host_assets[0]

        asset_id = None

        for child in host_asset.iter():

            if child.tag.split("}")[-1] == "id":

                if child.text:
                    asset_id = child.text.strip()
                    break

        if not asset_id:

            logger.warning(
                f"Qualys returned HostAsset for "
                f"{ip}, but no asset ID was found."
            )

            logger.debug(
                f"Qualys response for {ip}: "
                f"{response.text}"
            )

            return None

        logger.debug(
            f"Qualys IP {ip} -> Host Asset ID {asset_id}"
        )

        return asset_id

    except Exception as e:

        logger.error(
            f"Error searching Qualys Host Asset "
            f"for {ip}: {e}"
        )

        return None


def add_tag_to_host_asset(ip, tag_id):
    """
    Find a Qualys Host Asset by IP and add the
    specified static tag to it.
    """

    asset_id = get_qualys_host_asset_id(ip)

    if not asset_id:
        return False

    update_url = (
        "https://qualysapi.qualys.com/"
        f"qps/rest/2.0/update/am/hostasset/{asset_id}"
    )

    xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<ServiceRequest>
    <data>
        <HostAsset>
            <tags>
                <add>
                    <TagSimple>
                        <id>{tag_id}</id>
                    </TagSimple>
                </add>
            </tags>
        </HostAsset>
    </data>
</ServiceRequest>
"""

    try:

        response = requests.post(
            update_url,
            data=xml_payload.encode("utf-8"),
            auth=(qualys_user, qualys_pass),
            verify=False,
            headers={
                "Content-Type": "text/xml",
                "Accept": "text/xml",
                "X-Requested-With": "python-requests",
            },
            timeout=120,
        )

        if response.status_code != 200:

            print(
                f"[X] IP {ip} -> Tag {tag_id} "
                f"failed: HTTP {response.status_code}"
            )

            logger.error(
                f"Tag assignment failed: "
                f"IP={ip}, "
                f"Tag={tag_id}, "
                f"AssetID={asset_id}, "
                f"HTTP={response.status_code}"
            )

            logger.error(
                f"Response Headers: "
                f"{dict(response.headers)}"
            )

            logger.error(
                f"Response Body: "
                f"{response.text}"
            )

            return False

        # Qualys can return HTTP 200 with an XML
        # responseCode indicating success/failure.
        try:

            root = ET.fromstring(response.text)

            response_codes = [
                element.text.strip()
                for element in root.iter()
                if element.tag.split("}")[-1] == "responseCode"
                and element.text
            ]

            if response_codes:

                response_code = response_codes[0]

                if response_code.upper() != "SUCCESS":

                    print(
                        f"[X] IP {ip} -> Tag {tag_id} "
                        f"failed: Qualys responseCode "
                        f"{response_code}"
                    )

                    logger.error(
                        f"Tag assignment failed: "
                        f"IP={ip}, "
                        f"Tag={tag_id}, "
                        f"AssetID={asset_id}, "
                        f"responseCode={response_code}"
                    )

                    logger.error(
                        f"Response Body: "
                        f"{response.text}"
                    )

                    return False

        except ET.ParseError:

            # Do not automatically fail solely because
            # the response could not be parsed.
            logger.warning(
                f"Could not parse XML response for "
                f"IP {ip} -> Tag {tag_id}. "
                f"HTTP 200 received."
            )

        print(
            f"[✅] IP {ip} -> Tag {tag_id} "
            f"successfully added"
        )

        logger.info(
            f"Tag assignment successful: "
            f"IP={ip}, "
            f"Tag={tag_id}, "
            f"AssetID={asset_id}"
        )

        return True

    except Exception as e:

        print(
            f"[X] Error adding Tag {tag_id} "
            f"to IP {ip}: {e}"
        )

        logger.error(
            f"Error adding Tag {tag_id} "
            f"to IP {ip}: {e}"
        )

        logger.error(
            traceback.format_exc()
        )

        return False


# ---------------------------------------------------------
# Stage 1: Fetch IPs from SolarWinds
# ---------------------------------------------------------
stage_name = "Fetch IPs from SolarWinds"
stage_start(stage_name)

payload = {
    "query": (
        "SELECT IPAddress "
        "FROM Orion.Nodes "
        "WHERE Vendor LIKE '%Fortinet%'"
    )
}

try:

    print(
        "[*] Fetching Fortinet IPs "
        "from SolarWinds..."
    )

    response = requests.post(
        solarwinds_url,
        json=payload,
        auth=(username, password),
        verify=False
    )

    if response.status_code == 200:

        data = response.json()

        raw_ips = [
            row["IPAddress"]
            for row in data.get("results", [])
            if row.get("IPAddress")
        ]

        solarwinds_ips = sorted(
            set(raw_ips)
        )

        print(
            f"[✅] Found {len(solarwinds_ips)} "
            "Fortinet IPs in SolarWinds."
        )

        logger.info(
            f"SolarWinds returned "
            f"{len(solarwinds_ips)} unique IPs."
        )

    else:

        raise RuntimeError(
            f"Failed to fetch SolarWinds data: "
            f"HTTP {response.status_code}"
        )

except Exception as e:

    overall_ok = False

    stage_fail(stage_name, e)

    sys.exit(3)


# ---------------------------------------------------------
# Stage 2: Read CMDB IPs
# ---------------------------------------------------------
stage_name = "Read CMDB IPs from CSV"
stage_start(stage_name)

try:

    print(
        f"[*] Reading CMDB CSV: "
        f"{CMDB_CSV_FILE}"
    )

    cmdb_ips = read_cmdb_csv()

    print(
        f"[✅] CMDB IPs read: "
        f"{len(cmdb_ips)}"
    )

    logger.info(
        f"CMDB returned "
        f"{len(cmdb_ips)} unique IPs."
    )

except Exception as e:

    overall_ok = False

    stage_fail(stage_name, e)


# ---------------------------------------------------------
# Stage 3: Merge SolarWinds + CMDB
# ---------------------------------------------------------
stage_name = "Merge SolarWinds and CMDB IPs"
stage_start(stage_name)

try:

    solarwinds_set = set(
        solarwinds_ips
    )

    cmdb_set = set(
        cmdb_ips
    )

    common_ips = (
        solarwinds_set & cmdb_set
    )

    only_cmdb = (
        cmdb_set - solarwinds_set
    )

    only_solarwinds = (
        solarwinds_set - cmdb_set
    )

    merged_ips = sorted(
        solarwinds_set | cmdb_set
    )

    print(
        f"[*] SolarWinds IPs: "
        f"{len(solarwinds_ips)}"
    )

    print(
        f"[*] CMDB IPs: "
        f"{len(cmdb_ips)}"
    )

    print(
        f"[*] Common IPs: "
        f"{len(common_ips)}"
    )

    print(
        f"[*] Only CMDB: "
        f"{len(only_cmdb)}"
    )

    print(
        f"[*] Only SolarWinds: "
        f"{len(only_solarwinds)}"
    )

    print(
        f"[✅] Total merged IPs: "
        f"{len(merged_ips)}"
    )

    logger.info(
        f"Merged inventory: "
        f"SW={len(solarwinds_ips)}, "
        f"CMDB={len(cmdb_ips)}, "
        f"MERGED={len(merged_ips)}"
    )

    logger.debug(
        f"Merged IP list: "
        f"{merged_ips}"
    )

except Exception as e:

    overall_ok = False

    stage_fail(stage_name, e)

    merged_ips = sorted(
        set(solarwinds_ips)
    )


# ---------------------------------------------------------
# Stage 4: Read Tag Assignment CSV
# ---------------------------------------------------------
stage_name = "Read Tag Assignment CSV"
stage_start(stage_name)

try:

    print(
        f"[*] Reading tag assignment CSV: "
        f"{TAG_MAPPING_CSV}"
    )

    ip_to_tag_mapping = (
        read_tag_mapping_csv()
    )

    print(
        f"[✅] Tag assignment entries loaded: "
        f"{len(ip_to_tag_mapping)}"
    )

    logger.info(
        f"Tag assignment entries loaded: "
        f"{len(ip_to_tag_mapping)}"
    )

except Exception as e:

    overall_ok = False

    stage_fail(stage_name, e)


# ---------------------------------------------------------
# Stage 5: Correlate MERGED IPs -> Tags
#
# IMPORTANT:
# The merged IP list is the MASTER list.
#
# We loop through every merged IP and look for its
# tag assignment.
#
# IPs that exist only in the tag CSV are ignored.
# IPs in the merged list without a tag are reported.
# ---------------------------------------------------------
stage_name = "Correlate merged IPs with tag assignments"
stage_start(stage_name)

try:

    tag_to_ips_mapping = {}
    unmapped_ips = []

    for ip in merged_ips:

        if ip in ip_to_tag_mapping:

            tag_id = (
                ip_to_tag_mapping[ip]
            )

            if tag_id not in tag_to_ips_mapping:
                tag_to_ips_mapping[tag_id] = []

            tag_to_ips_mapping[tag_id].append(ip)

        else:

            unmapped_ips.append(ip)

    print(
        "\n" + "=" * 70
    )

    print(
        "[📋] TAG ASSIGNMENT VALIDATION"
    )

    print(
        "=" * 70
    )

    print(
        f"Merged IPs                  : "
        f"{len(merged_ips)}"
    )

    print(
        f"IPs with Tag Assignment    : "
        f"{len(merged_ips) - len(unmapped_ips)}"
    )

    print(
        f"IPs Missing Tag Assignment : "
        f"{len(unmapped_ips)}"
    )

    print(
        "-" * 70
    )

    logger.info(
        "TAG ASSIGNMENT VALIDATION"
    )

    logger.info(
        f"Merged IPs: "
        f"{len(merged_ips)}"
    )

    logger.info(
        f"IPs with Tag Assignment: "
        f"{len(merged_ips) - len(unmapped_ips)}"
    )

    logger.info(
        f"IPs Missing Tag Assignment: "
        f"{len(unmapped_ips)}"
    )

    if unmapped_ips:

        print(
            "[⚠️] IPs missing from "
            "Tag Assignment CSV:"
        )

        logger.warning(
            "IPs missing from Tag Assignment CSV:"
        )

        for ip in unmapped_ips:

            print(
                f"    {ip}"
            )

            logger.warning(
                f"MISSING TAG ASSIGNMENT: "
                f"{ip}"
            )

        print(
            "-" * 70
        )

    else:

        print(
            "[✅] Every merged IP has "
            "a tag assignment."
        )

        logger.info(
            "Every merged IP has "
            "a tag assignment."
        )

    # Show final tag grouping
    for tag_id in sorted(
        tag_to_ips_mapping
    ):

        ips = (
            tag_to_ips_mapping[tag_id]
        )

        print(
            f"\nTag {tag_id}: "
            f"{len(ips)} IPs"
        )

        logger.info(
            f"Tag {tag_id}: "
            f"{len(ips)} IPs"
        )

        for ip in ips:

            logger.debug(
                f"Tag {tag_id} <- {ip}"
            )

    print(
        "=" * 70
    )

except Exception as e:

    overall_ok = False

    stage_fail(
        stage_name,
        e
    )


# ---------------------------------------------------------
# Stage 6: Optional Asset Group
# ---------------------------------------------------------
if UPDATE_QUALYS_ASSET_GROUP:

    stage_name = (
        "Update Qualys Asset Group "
        "with all merged IPs"
    )

    stage_start(stage_name)

    try:

        clear_data = {
            "action": "edit",
            "id": qualys_group_id,
            "set_ips": ""
        }

        clear_resp = requests.post(
            qualys_url,
            data=clear_data,
            auth=(
                qualys_user,
                qualys_pass
            ),
            verify=False,
            headers={
                "X-Requested-With":
                "python-requests"
            },
            timeout=60
        )

        if clear_resp.status_code != 200:

            raise RuntimeError(
                f"Qualys clear failed: "
                f"HTTP {clear_resp.status_code}"
            )

        print(
            "[✅] Cleared existing IPs "
            "from Asset Group."
        )

        edit_data = {
            "action": "edit",
            "id": qualys_group_id,
            "set_ips": ",".join(merged_ips)
        }

        edit_response = requests.post(
            qualys_url,
            data=edit_data,
            auth=(
                qualys_user,
                qualys_pass
            ),
            verify=False,
            headers={
                "X-Requested-With":
                "python-requests"
            },
            timeout=60
        )

        if edit_response.status_code != 200:

            raise RuntimeError(
                f"Asset Group update failed: "
                f"HTTP "
                f"{edit_response.status_code} - "
                f"{edit_response.text}"
            )

        print(
            f"[✅] Successfully synced "
            f"{len(merged_ips)} IPs to "
            f"Asset Group "
            f"{qualys_group_id}."
        )

        logger.info(
            f"Asset Group "
            f"{qualys_group_id} updated "
            f"with "
            f"{len(merged_ips)} merged IPs."
        )

    except Exception as e:

        overall_ok = False

        stage_fail(
            stage_name,
            e
        )

else:

    print(
        "\n[*] Asset Group update disabled; "
        "skipping Asset Group update."
    )

    logger.info(
        "Asset Group update skipped because "
        "UPDATE_QUALYS_ASSET_GROUP=false."
    )


# ---------------------------------------------------------
# Stage 7: Authentication Record
# ---------------------------------------------------------
if AUTH_RECORD_ID and merged_ips:

    stage_name = (
        f"Update Qualys authentication "
        f"record ID {AUTH_RECORD_ID}"
    )

    stage_start(stage_name)

    try:

        update_payload = {
            "action": "update",
            "ids": AUTH_RECORD_ID,
            "ips": ",".join(merged_ips),
            "echo_request": "1"
        }

        update_resp = requests.post(
            QUALYS_AUTH_UPDATE_URL,
            data=update_payload,
            auth=(
                qualys_user,
                qualys_pass
            ),
            verify=False,
            headers={
                "X-Requested-With":
                "python-requests"
            },
            timeout=120
        )

        if update_resp.status_code != 200:

            raise RuntimeError(
                f"Auth record update failed: "
                f"HTTP "
                f"{update_resp.status_code} - "
                f"{update_resp.text}"
            )

        print(
            f"[✅] Successfully updated "
            f"Auth Record "
            f"{AUTH_RECORD_ID}."
        )

        logger.info(
            f"Authentication record "
            f"{AUTH_RECORD_ID} updated."
        )

    except Exception as e:

        overall_ok = False

        stage_fail(
            stage_name,
            e
        )

else:

    logger.info(
        "Authentication record update skipped "
        "because AUTH_RECORD_ID is not configured."
    )


# ---------------------------------------------------------
# Stage 8: Update Qualys Tags
#
# IMPORTANT:
# Only MERGED IPs that have a tag assignment
# are processed.
# ---------------------------------------------------------
if tag_to_ips_mapping:

    stage_name = (
        "Update Qualys Asset Tags"
    )

    stage_start(stage_name)

    try:

        print(
            f"[*] Updating "
            f"{len(tag_to_ips_mapping)} "
            f"Qualys tags..."
        )

        ips_successful = 0
        ips_failed = 0

        for tag_id in sorted(
            tag_to_ips_mapping
        ):

            ips = (
                tag_to_ips_mapping[tag_id]
            )

            print(
                f"\n[*] Processing Tag "
                f"{tag_id}: "
                f"{len(ips)} IPs"
            )

            logger.info(
                f"Processing Tag "
                f"{tag_id}: "
                f"{len(ips)} IPs"
            )

            for ip in ips:

                if add_tag_to_host_asset(
                    ip,
                    tag_id
                ):

                    ips_successful += 1

                else:

                    ips_failed += 1
                    overall_ok = False

        print(
            "\n" + "=" * 70
        )

        print(
            "[📊] TAG UPDATE SUMMARY"
        )

        print(
            "=" * 70
        )

        print(
            f"Successful IP tag assignments : "
            f"{ips_successful}"
        )

        print(
            f"Failed IP tag assignments     : "
            f"{ips_failed}"
        )

        print(
            f"Missing tag assignments       : "
            f"{len(unmapped_ips)}"
        )

        print(
            "=" * 70
        )

        logger.info(
            f"Tag update summary: "
            f"successful={ips_successful}, "
            f"failed={ips_failed}, "
            f"missing_assignments="
            f"{len(unmapped_ips)}"
        )

    except Exception as e:

        overall_ok = False

        stage_fail(
            stage_name,
            e
        )

else:

    print(
        "\n[*] No valid tag assignments "
        "found for the merged IP list; "
        "skipping tag updates."
    )

    logger.warning(
        "No merged IPs had tag assignments; "
        "Qualys tag update skipped."
    )


# ---------------------------------------------------------
# Final Summary
# ---------------------------------------------------------
print(
    "\n" + "=" * 70
)

print(
    "[📊] FINAL SUMMARY"
)

print(
    "=" * 70
)

print(
    f"SolarWinds IPs fetched       : "
    f"{len(solarwinds_ips)}"
)

print(
    f"CMDB IPs read                : "
    f"{len(cmdb_ips)}"
)

print(
    f"Total merged IPs             : "
    f"{len(merged_ips)}"
)

print(
    f"IPs with tag assignment      : "
    f"{len(merged_ips) - len(unmapped_ips)}"
)

print(
    f"IPs missing tag assignment   : "
    f"{len(unmapped_ips)}"
)

print(
    f"Qualys tags processed        : "
    f"{len(tag_to_ips_mapping)}"
)

if UPDATE_QUALYS_ASSET_GROUP:

    print(
        f"Asset Group "
        f"{qualys_group_id} : Updated"
    )

else:

    print(
        "Asset Group                  : Skipped"
    )

print(
    "=" * 70
)

logger.info(
    f"FINAL SUMMARY: "
    f"SW={len(solarwinds_ips)}, "
    f"CMDB={len(cmdb_ips)}, "
    f"MERGED={len(merged_ips)}, "
    f"MAPPED="
    f"{len(merged_ips)-len(unmapped_ips)}, "
    f"UNMAPPED={len(unmapped_ips)}, "
    f"TAGS={len(tag_to_ips_mapping)}"
)

if overall_ok:

    logger.info(
        "Script completed successfully."
    )

    print(
        "\n✅ Script Execution Successfully! "
        "Please check the log file for details.",
        file=ORIGINAL_STDOUT
    )

    sys.exit(0)

else:

    logger.error(
        "Script completed with failures."
    )

    print(
        "\n❌ Script Execution completed "
        "with failures. "
        "Please check the log file for details.",
        file=ORIGINAL_STDOUT
    )

    sys.exit(7)
