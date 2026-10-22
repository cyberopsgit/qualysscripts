#!/usr/bin/env python3
"""Qualys VM/VMDR password updater for basic UNIX and Windows auth records.

Files beside this script:
  .env
  authentication_record.xlsx

Excel columns: id, title, username, password, type

This performs LIVE updates automatically; no --apply flag or confirmation prompt.
Review the IDs and passwords before running.
"""

import os
import sys
import subprocess
import importlib.util
import logging
from pathlib import Path
from datetime import datetime
from xml.etree import ElementTree as ET

# Automatically install missing dependencies.
PACKAGES = {
    "requests": "requests",
    "pandas": "pandas",
    "openpyxl": "openpyxl",
    "dotenv": "python-dotenv",
}
for module, package in PACKAGES.items():
    if importlib.util.find_spec(module) is None:
        print(f"[INFO] Installing missing dependency: {package}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        except subprocess.CalledProcessError:
            print(f"[ERROR] Could not install {package}. Check network/pip permissions.")
            sys.exit(1)

import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# Configuration
SCRIPT_DIR = Path(__file__).resolve().parent
ENV_FILE = SCRIPT_DIR / ".env"
INPUT_FILE = SCRIPT_DIR / "authentication_record.xlsx"
QUALYS_BASE_URL = "https://qualysapi.qualys.com"  # Change only if your API region differs.
API_VERSION = "3.0"
TIMEOUT_SECONDS = 60
TYPE_ENDPOINTS = {"unix": "unix", "windows": "windows"}

load_dotenv(ENV_FILE)
QUALYS_USERNAME = os.getenv("QUALYS_USERNAME", "").strip()
QUALYS_PASSWORD = os.getenv("QUALYS_PASSWORD", "")

STAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = SCRIPT_DIR / f"qualys_password_update_{STAMP}.log"
REPORT_FILE = SCRIPT_DIR / f"qualys_password_update_report_{STAMP}.csv"
REQUIRED_COLUMNS = {"id", "title", "username", "password", "type"}

# Logging
logger = logging.getLogger("QualysPasswordUpdate")
logger.setLevel(logging.INFO)
logger.handlers.clear()
logger.propagate = False
formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setFormatter(formatter)
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)


def validate_config():
    if not QUALYS_BASE_URL.startswith("https://"):
        raise ValueError("Qualys API Base URL must use HTTPS.")
    if not QUALYS_USERNAME or not QUALYS_PASSWORD:
        raise ValueError("QUALYS_USERNAME or QUALYS_PASSWORD is missing from .env.")


def load_excel():
    if not INPUT_FILE.is_file():
        raise FileNotFoundError(f"Excel file not found: {INPUT_FILE}")
    df = pd.read_excel(INPUT_FILE, dtype=str, keep_default_na=False)
    df.columns = [str(c).strip().lower() for c in df.columns]
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError("Missing Excel columns: " + ", ".join(sorted(missing)))
    if df.empty:
        raise ValueError("Excel file contains no records.")

    for col in ("id", "title", "username", "type"):
        df[col] = df[col].str.strip()
    df["password"] = df["password"].astype(str)  # Preserve spaces in passwords.

    if not df["id"].str.fullmatch(r"\d+").all():
        raise ValueError("Every ID must be a numeric Qualys authentication record ID.")
    if df["id"].duplicated().any():
        dupes = df.loc[df["id"].duplicated(keep=False), "id"].tolist()
        raise ValueError(f"Duplicate record IDs found: {dupes}")
    for col in ("title", "username", "password", "type"):
        if (df[col] == "").any():
            raise ValueError(f"Blank value found in Excel column '{col}'.")
    df["type"] = df["type"].str.lower()
    return df


def create_session():
    session = requests.Session()
    session.auth = HTTPBasicAuth(QUALYS_USERNAME, QUALYS_PASSWORD)
    session.headers.update({
        "X-Requested-With": "QualysPasswordUpdateScript",
        "Accept": "application/xml",
    })
    return session


def parse_update_response(response_text, expected_id):
    try:
        root = ET.fromstring(response_text)
    except ET.ParseError:
        return False, "Qualys returned invalid XML."

    batches = [n for n in root.iter() if n.tag.split("}")[-1].upper() == "BATCH"]
    for batch in batches:
        messages = [
            (n.text or "").strip() for n in batch.iter()
            if n.tag.split("}")[-1].upper() == "TEXT"
        ]
        ids = [
            (n.text or "").strip() for n in batch.iter()
            if n.tag.split("}")[-1].upper() == "ID"
        ]
        if expected_id in ids:
            message = "; ".join(messages) or "No status message returned."
            if any("successfully updated" in m.lower() for m in messages):
                return True, message
            return False, message

    messages = [
        (n.text or "").strip() for n in root.iter()
        if n.tag.split("}")[-1].upper() in {"TEXT", "ERRORMESSAGE"}
    ]
    return False, "; ".join(m for m in messages if m) or (
        f"No update confirmation for record ID {expected_id}."
    )


def update_record(session, record):
    endpoint_type = TYPE_ENDPOINTS.get(record["type"])
    if not endpoint_type:
        return "SKIPPED", f"Unsupported type '{record['type']}'."

    url = f"{QUALYS_BASE_URL}/api/{API_VERSION}/fo/auth/{endpoint_type}/"
    # This supports basic username/password records only, not vault-backed records.
    payload = {
        "action": "update",
        "ids": record["id"],
        "username": record["username"],
        "password": record["password"],
    }
    response = session.post(url, data=payload, timeout=TIMEOUT_SECONDS)
    if not response.ok:
        return "FAILED", f"HTTP status {response.status_code}"
    success, message = parse_update_response(response.text, record["id"])
    return ("SUCCESS" if success else "FAILED"), message


def main():
    logger.info("=" * 72)
    logger.info("QUALYS AUTHENTICATION PASSWORD UPDATE STARTED")
    logger.info("API version: %s", API_VERSION)
    logger.info("Input file: %s", INPUT_FILE.name)
    logger.info("Log file: %s", LOG_FILE.name)
    logger.info("Report file: %s", REPORT_FILE.name)
    logger.info("=" * 72)

    session = None
    results = []
    try:
        validate_config()
        df = load_excel()
        total = len(df)
        supported = df[df["type"].isin(TYPE_ENDPOINTS)]
        unsupported = df[~df["type"].isin(TYPE_ENDPOINTS)]

        print("\n" + "=" * 72)
        print("QUALYS PASSWORD UPDATE - PRE-UPDATE SUMMARY")
        print("=" * 72)
        print(f"Total records in Excel       : {total}")
        print(f"Supported records to update  : {len(supported)}")
        print(f"Unsupported records to skip  : {len(unsupported)}")
        print(f"Log file                     : {LOG_FILE.name}")
        print(f"CSV report                   : {REPORT_FILE.name}")
        print("=" * 72)
        print("\nStarting updates automatically; no confirmation required.")

        logger.info("Total records in Excel: %d", total)
        logger.info("Supported records to update: %d", len(supported))
        logger.info("Unsupported records to skip: %d", len(unsupported))

        for _, row in unsupported.iterrows():
            message = f"Unsupported type '{row['type']}'."
            logger.warning("SKIPPED | ID=%s | Title=%s | %s", row["id"], row["title"], message)
            results.append({
                "id": row["id"], "title": row["title"], "username": row["username"],
                "type": row["type"], "status": "SKIPPED", "message": message,
            })

        success_count = failed_count = error_count = 0
        session = create_session()

        for idx, (_, row) in enumerate(supported.iterrows(), start=1):
            record = row.to_dict()
            logger.info("-" * 72)
            logger.info("Processing %d/%d | ID=%s | Title=%s | Type=%s",
                        idx, len(supported), record["id"], record["title"], record["type"])
            try:
                status, message = update_record(session, record)
                if status == "SUCCESS":
                    success_count += 1
                    logger.info("SUCCESS | ID=%s | %s", record["id"], message)
                else:
                    failed_count += 1
                    logger.error("FAILED | ID=%s | %s", record["id"], message)
            except requests.Timeout:
                status = "ERROR"
                message = "Request timed out; verify status in Qualys before retrying."
                error_count += 1
                logger.error("ERROR | ID=%s | %s", record["id"], message)
            except requests.RequestException as exc:
                status = "ERROR"
                message = f"Network/request error: {type(exc).__name__}"
                error_count += 1
                logger.error("ERROR | ID=%s | %s", record["id"], message)
            except Exception as exc:
                status = "ERROR"
                message = f"Unexpected error: {type(exc).__name__}"
                error_count += 1
                logger.exception("ERROR | ID=%s", record["id"])

            results.append({
                "id": record["id"], "title": record["title"],
                "username": record["username"], "type": record["type"],
                "status": status, "message": message,
            })

        pd.DataFrame(results).to_csv(REPORT_FILE, index=False)

        logger.info("=" * 72)
        logger.info("EXECUTION SUMMARY")
        logger.info("Total records       : %d", total)
        logger.info("Successful updates  : %d", success_count)
        logger.info("Failed updates      : %d", failed_count)
        logger.info("Execution errors    : %d", error_count)
        logger.info("Skipped records     : %d", len(unsupported))
        logger.info("Failed/unconfirmed  : %d", failed_count + error_count)
        logger.info("Log file            : %s", LOG_FILE.name)
        logger.info("CSV report          : %s", REPORT_FILE.name)
        logger.info("=" * 72)
        logger.info("SCRIPT COMPLETED SUCCESSFULLY")
        print("\nSCRIPT COMPLETED SUCCESSFULLY")
    finally:
        if session is not None:
            session.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        logger.exception("FATAL ERROR: %s", str(exc))
        print(f"\nSCRIPT FAILED: {exc}")
        sys.exit(1)
