#!/usr/bin/env python3
"""
Qualys Authentication Record Password Updater.

Required files in the same folder:
  authentication_record.xlsx
  .env

Required Excel columns (case-insensitive):
  id, Title, username, password, Type

Required .env entries:
  QUALYS_USERNAME=your_api_username
  QUALYS_PASSWORD=your_api_password

Run:
  python qualys_password_update.py

Live updates start automatically without a confirmation prompt.
Passwords are never written to logs or the CSV report.
"""

import os
import sys
import subprocess
import importlib.util
import logging
import csv
import traceback
from pathlib import Path
from datetime import datetime
from xml.etree import ElementTree as ET

# ============================================================
# INSTALL MISSING DEPENDENCIES
# ============================================================

REQUIRED_PACKAGES = {
    "requests": "requests",
    "pandas": "pandas",
    "openpyxl": "openpyxl",
    "dotenv": "python-dotenv",
}

for module_name, package_name in REQUIRED_PACKAGES.items():
    if importlib.util.find_spec(module_name) is None:
        print(f"[INFO] Installing missing dependency: {package_name}")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", package_name
            ])
        except subprocess.CalledProcessError:
            print(f"SCRIPT FAILED: Could not install {package_name}.")
            sys.exit(1)

import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# ============================================================
# CONFIGURATION
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent
ENV_FILE = SCRIPT_DIR / ".env"
INPUT_FILE = SCRIPT_DIR / "authentication_record.xlsx"

# IMPORTANT:
# Set this to the exact API Server URL shown in Qualys Help > About.
QUALYS_BASE_URL = "https://qualysapi.qualys.com"

load_dotenv(ENV_FILE)

QUALYS_USERNAME = os.getenv("QUALYS_USERNAME", "").strip()
QUALYS_PASSWORD = os.getenv("QUALYS_PASSWORD", "")

# Optional: trusted CA bundle path for corporate TLS inspection.
# Example .env entry:
# QUALYS_CA_BUNDLE=C:\certificates\corporate-ca-bundle.pem
#
# TLS verification remains enabled by default.
CA_BUNDLE = os.getenv("QUALYS_CA_BUNDLE", "").strip()
TLS_VERIFY = CA_BUNDLE if CA_BUNDLE else True

TIMEOUT_SECONDS = 60

TYPE_ENDPOINTS = {
    "unix": "unix",
    "windows": "windows",
}

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

LOG_FILE = SCRIPT_DIR / f"qualys_password_update_{TIMESTAMP}.log"
REPORT_FILE = SCRIPT_DIR / f"qualys_password_update_report_{TIMESTAMP}.csv"

REQUIRED_COLUMNS = {
    "id",
    "title",
    "username",
    "password",
    "type",
}

# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger("QualysPasswordUpdate")
logger.setLevel(logging.DEBUG)
logger.handlers.clear()
logger.propagate = False

formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

file_handler = logging.FileHandler(
    LOG_FILE,
    encoding="utf-8",
    mode="a",
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

# ============================================================
# VALIDATE CONFIGURATION
# ============================================================

def validate_config():
    if not QUALYS_BASE_URL.startswith("https://"):
        raise ValueError(
            "QUALYS_BASE_URL must use HTTPS."
        )

    if not QUALYS_USERNAME or not QUALYS_PASSWORD:
        raise ValueError(
            "QUALYS_USERNAME or QUALYS_PASSWORD is missing from .env."
        )

    if CA_BUNDLE and not Path(CA_BUNDLE).is_file():
        raise ValueError(
            "QUALYS_CA_BUNDLE was configured, but the certificate "
            "bundle file does not exist."
        )


# ============================================================
# LOAD AND VALIDATE EXCEL
# ============================================================

def load_excel():
    if not INPUT_FILE.is_file():
        raise FileNotFoundError(
            f"Excel file not found: {INPUT_FILE}"
        )

    df = pd.read_excel(
        INPUT_FILE,
        dtype=str,
        keep_default_na=False,
    )

    df.columns = [
        str(column).strip().lower()
        for column in df.columns
    ]

    missing = REQUIRED_COLUMNS - set(df.columns)

    if missing:
        raise ValueError(
            "Missing Excel columns: "
            + ", ".join(sorted(missing))
        )

    if df.empty:
        raise ValueError(
            "Excel file contains no records."
        )

    for column in ("id", "title", "username", "type"):
        df[column] = df[column].astype(str).str.strip()

    # Do not strip passwords because spaces may be intentional.
    df["password"] = df["password"].astype(str)

    df["type"] = df["type"].str.lower()

    if not df["id"].str.fullmatch(r"\d+").all():
        raise ValueError(
            "Every authentication record ID must contain digits only."
        )

    if df["id"].duplicated().any():
        duplicates = df.loc[
            df["id"].duplicated(keep=False), "id"
        ].tolist()

        raise ValueError(
            f"Duplicate authentication record IDs found: {duplicates}"
        )

    for column in ("title", "username", "password", "type"):
        if (df[column] == "").any():
            raise ValueError(
                f"Blank value found in Excel column '{column}'."
            )

    return df


# ============================================================
# CREATE QUALYS SESSION
# ============================================================

def create_session():
    session = requests.Session()

    session.auth = HTTPBasicAuth(
        QUALYS_USERNAME,
        QUALYS_PASSWORD,
    )

    session.headers.update({
        "X-Requested-With": "QualysPasswordUpdateScript",
        "Accept": "application/xml",
    })

    # Never disable certificate verification to bypass SSL errors.
    session.verify = TLS_VERIFY

    return session


# ============================================================
# XML RESPONSE HELPERS
# ============================================================

def xml_name(tag):
    """Normalize XML element names, including namespace-qualified names."""
    return tag.split("}")[-1].upper()


def is_explicit_success(message):
    """Accept only an explicit update-success message."""
    lowered = message.lower()

    return (
        "successfully updated" in lowered
        or "successfully updated authentication" in lowered
        or "update successful" in lowered
    )


def contains_error(message):
    """Reject responses containing error indicators."""
    lowered = message.lower()

    error_terms = (
        "error",
        "failed",
        "failure",
        "invalid",
        "not updated",
        "denied",
    )

    return any(term in lowered for term in error_terms)


def parse_update_response(response_text, expected_id):
    """
    A record is successful only when:
      1. Qualys returns parseable XML.
      2. The expected record ID is present.
      3. An explicit successful-update message is present.
      4. No error indicators are present.

    Ambiguous responses are treated as FAILED.
    """

    try:
        root = ET.fromstring(response_text)
    except ET.ParseError:
        return False, "Qualys response was not valid XML."

    all_ids = [
        (node.text or "").strip()
        for node in root.iter()
        if xml_name(node.tag) == "ID"
    ]

    all_messages = [
        (node.text or "").strip()
        for node in root.iter()
        if xml_name(node.tag)
        in {"TEXT", "ERRORMESSAGE", "MESSAGE"}
    ]

    # Prefer a BATCH result that associates the expected ID and message.
    batches = [
        node for node in root.iter()
        if xml_name(node.tag) == "BATCH"
    ]

    for batch in batches:
        batch_ids = [
            (node.text or "").strip()
            for node in batch.iter()
            if xml_name(node.tag) == "ID"
        ]

        if expected_id not in batch_ids:
            continue

        batch_messages = [
            (node.text or "").strip()
            for node in batch.iter()
            if xml_name(node.tag)
            in {"TEXT", "ERRORMESSAGE", "MESSAGE"}
        ]

        message = "; ".join(
            item for item in batch_messages if item
        )

        if not message:
            return False, (
                "Matching record ID returned without a status message."
            )

        if contains_error(message):
            return False, message

        if is_explicit_success(message):
            return True, message

        return False, (
            f"Qualys did not explicitly confirm success: {message}"
        )

    # Handle a single-record response without a BATCH element.
    # Only accept it if the expected ID and a clear success message exist.
    if expected_id not in all_ids:
        detail = "; ".join(
            item for item in all_messages if item
        )

        return False, (
            f"Response did not confirm expected record ID {expected_id}"
            + (f": {detail}" if detail else ".")
        )

    combined_message = "; ".join(
        item for item in all_messages if item
    )

    if not combined_message:
        return False, (
            "Qualys returned the record ID but no status message."
        )

    if contains_error(combined_message):
        return False, combined_message

    if is_explicit_success(combined_message):
        return True, combined_message

    return False, (
        f"Qualys did not explicitly confirm success: {combined_message}"
    )


# ============================================================
# UPDATE ONE AUTHENTICATION RECORD
# ============================================================

def update_record(session, record):
    record_type = record["type"]
    endpoint_type = TYPE_ENDPOINTS.get(record_type)

    if endpoint_type is None:
        return "FAILED", (
            f"Unsupported record type '{record_type}'. "
            "Only UNIX and Windows are supported."
        )

    url = (
        f"{QUALYS_BASE_URL.rstrip('/')}"
        f"/api/2.0/fo/auth/{endpoint_type}/"
    )

    payload = {
        "action": "update",
        "ids": record["id"],
        "username": record["username"],
        "password": record["password"],
    }

    response = session.post(
        url,
        data=payload,
        timeout=TIMEOUT_SECONDS,
    )

    if not response.ok:
        # Do not write the response body to the log/report.
        return "FAILED", (
            f"HTTP {response.status_code} returned by Qualys."
        )

    success, message = parse_update_response(
        response.text,
        record["id"],
    )

    if success:
        return "SUCCESS", message

    return "FAILED", message


# ============================================================
# WRITE CSV REPORT
# ============================================================

def write_report(results):
    columns = [
        "id",
        "title",
        "username",
        "type",
        "status",
        "message",
    ]

    with REPORT_FILE.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=columns,
        )

        writer.writeheader()
        writer.writerows(results)


# ============================================================
# MAIN EXECUTION
# ============================================================

def main():
    session = None
    results = []
    df = None
    fatal_error = None

    logger.info("=" * 72)
    logger.info("QUALYS AUTHENTICATION PASSWORD UPDATE STARTED")
    logger.info("API base URL: %s", QUALYS_BASE_URL)
    logger.info("Input file: %s", INPUT_FILE.name)
    logger.info("Log file: %s", LOG_FILE.name)
    logger.info("CSV report: %s", REPORT_FILE.name)
    logger.info("=" * 72)

    try:
        validate_config()
        df = load_excel()

        total = len(df)

        supported_count = int(
            df["type"].isin(TYPE_ENDPOINTS).sum()
        )

        unsupported_count = total - supported_count

        print("\n" + "=" * 72)
        print("QUALYS PASSWORD UPDATE - PRE-UPDATE SUMMARY")
        print("=" * 72)
        print(f"Total records in Excel         : {total}")
        print(f"Supported records to update    : {supported_count}")
        print(f"Unsupported records (will fail): {unsupported_count}")
        print(f"Log file                       : {LOG_FILE.name}")
        print(f"CSV report                     : {REPORT_FILE.name}")
        print("\nStarting updates automatically; no confirmation required.")

        logger.info(
            "Total records=%d | Supported=%d | Unsupported=%d",
            total,
            supported_count,
            unsupported_count,
        )

        session = create_session()

        for position, (_, row) in enumerate(
            df.iterrows(),
            start=1,
        ):
            record = row.to_dict()

            logger.info(
                "Processing %d/%d | ID=%s | Title=%s | Type=%s",
                position,
                total,
                record["id"],
                record["title"],
                record["type"],
            )

            try:
                status, message = update_record(
                    session,
                    record,
                )

            except requests.exceptions.SSLError as exc:
                # This is the error seen in your screenshots.
                # The detailed exception helps diagnose TLS configuration.
                detail = str(exc).replace("\n", " ").strip()

                status = "FAILED"
                message = (
                    "SSL/TLS connection failed. Verify QUALYS_BASE_URL "
                    "against Qualys Help > About > API Server URL. "
                    "If the URL is correct, check the corporate proxy "
                    "and trusted CA configuration. "
                    f"Details: {detail[:350]}"
                )

            except requests.Timeout:
                status = "FAILED"
                message = (
                    "Request timed out; update outcome is unconfirmed. "
                    "Check the record in Qualys before retrying."
                )

            except requests.RequestException as exc:
                status = "FAILED"
                message = (
                    f"Network/request error: {type(exc).__name__}."
                )

            except Exception as exc:
                status = "FAILED"
                message = (
                    f"Unexpected record error: {type(exc).__name__}."
                )

                logger.debug(
                    "Unexpected exception for record ID %s:\n%s",
                    record["id"],
                    traceback.format_exc(),
                )

            results.append({
                "id": record["id"],
                "title": record["title"],
                "username": record["username"],
                "type": record["type"],
                "status": status,
                "message": message,
            })

            if status == "SUCCESS":
                logger.info(
                    "SUCCESS | ID=%s | %s",
                    record["id"],
                    message,
                )
            else:
                logger.error(
                    "FAILED | ID=%s | %s",
                    record["id"],
                    message,
                )

        write_report(results)

    except Exception as exc:
        fatal_error = f"{type(exc).__name__}: {exc}"
        logger.exception("FATAL ERROR: %s", fatal_error)

    finally:
        if session is not None:
            session.close()

    # A setup or validation error must never result in a success message.
    if fatal_error:
        print("\nSCRIPT FAILED")
        print(f"Reason: {fatal_error}")
        print(f"Log file: {LOG_FILE}")
        sys.exit(1)

    total = len(results)

    success_count = sum(
        item["status"] == "SUCCESS"
        for item in results
    )

    failed_count = total - success_count

    unsupported_count = sum(
        item["message"].startswith("Unsupported record type")
        for item in results
    )

    logger.info("=" * 72)
    logger.info("FINAL EXECUTION SUMMARY")
    logger.info("Total records attempted : %d", total)
    logger.info("Successful updates      : %d", success_count)
    logger.info("Failed/unconfirmed      : %d", failed_count)
    logger.info("Unsupported types       : %d", unsupported_count)
    logger.info("CSV report              : %s", REPORT_FILE.name)
    logger.info("Log file                : %s", LOG_FILE.name)

    print("\n" + "=" * 72)
    print("FINAL EXECUTION SUMMARY")
    print("=" * 72)
    print(f"Total records attempted : {total}")
    print(f"Successful updates      : {success_count}")
    print(f"Failed/unconfirmed      : {failed_count}")
    print(f"Unsupported types       : {unsupported_count}")
    print(f"CSV report              : {REPORT_FILE.name}")
    print(f"Log file                : {LOG_FILE.name}")

    # Overall success is permitted only when every row is confirmed.
    all_confirmed = (
        total > 0
        and success_count == total
        and failed_count == 0
        and unsupported_count == 0
    )

    if all_confirmed:
        logger.info(
            "SCRIPT COMPLETED SUCCESSFULLY - "
            "ALL PASSWORD UPDATES CONFIRMED"
        )

        print(
            "\nSCRIPT COMPLETED SUCCESSFULLY - "
            "ALL PASSWORD UPDATES CONFIRMED"
        )

        sys.exit(0)

    logger.error(
        "SCRIPT FAILED - ONE OR MORE UPDATES FAILED OR WERE UNCONFIRMED"
    )

    print(
        "\nSCRIPT FAILED - "
        "ONE OR MORE UPDATES FAILED OR WERE UNCONFIRMED"
    )

    sys.exit(1)


if __name__ == "__main__":
    main()