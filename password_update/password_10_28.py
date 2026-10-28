
#!/usr/bin/env python3

import os
import sys
import csv
import logging
import subprocess
import importlib.util
import traceback
from pathlib import Path
from datetime import datetime
from xml.etree import ElementTree as ET

# ============================================================
# INSTALL REQUIRED DEPENDENCIES
# ============================================================

PACKAGES = {
    "requests": "requests",
    "pandas": "pandas",
    "openpyxl": "openpyxl",
    "dotenv": "python-dotenv",
}

for module_name, package_name in PACKAGES.items():
    if importlib.util.find_spec(module_name) is None:
        print(f"[INFO] Installing {package_name}")

        try:
            subprocess.check_call([
                sys.executable,
                "-m",
                "pip",
                "install",
                package_name,
            ])
        except subprocess.CalledProcessError:
            print(f"[FAILED] Could not install {package_name}")
            sys.exit(1)

import pandas as pd
import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# ============================================================
# CONFIGURATION
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent

ENV_FILE = SCRIPT_DIR / ".env"

EXCEL_FILE = SCRIPT_DIR / "authentication_record.xlsx"

load_dotenv(ENV_FILE)

QUALYS_USER = os.getenv("QUALYS_USER")
QUALYS_PASS = os.getenv("QUALYS_PASS")

QUALYS_GROUP_ID = os.getenv("QUALYS_GROUP_ID")
AUTH_RECORD_ID = os.getenv("AUTH_RECORD_ID")

# API URL from your previous working script
QUALYS_URL = (
    "https://qualysapi.qualys.com"
    "/api/2.0/fo/auth/unix/"
)

QUALYS_WINDOWS_URL = (
    "https://qualysapi.qualys.com"
    "/api/2.0/fo/auth/windows/"
)

# Optional CA bundle from your IT/security team.
# SSL verification remains enabled.
QUALYS_CA_BUNDLE = os.getenv(
    "QUALYS_CA_BUNDLE",
    "",
).strip()

TLS_VERIFY = (
    QUALYS_CA_BUNDLE
    if QUALYS_CA_BUNDLE
    else True
)

TIMEOUT = 60

TIMESTAMP = datetime.now().strftime(
    "%Y%m%d_%H%M%S"
)

LOG_FILE = SCRIPT_DIR / (
    f"qualys_password_update_{TIMESTAMP}.log"
)

CSV_FILE = SCRIPT_DIR / (
    f"qualys_password_update_report_{TIMESTAMP}.csv"
)

# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger("QualysPasswordUpdate")

logger.setLevel(logging.DEBUG)

logger.handlers.clear()

logger.propagate = False

formatter = logging.Formatter(
    "%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

file_handler = logging.FileHandler(
    LOG_FILE,
    encoding="utf-8",
)

file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler(sys.stdout)

console_handler.setFormatter(formatter)

logger.addHandler(file_handler)

logger.addHandler(console_handler)

# ============================================================
# VALIDATE CONFIGURATION
# ============================================================

def validate_config():

    if not QUALYS_USER:
        raise ValueError(
            "QUALYS_USER is missing from .env"
        )

    if not QUALYS_PASS:
        raise ValueError(
            "QUALYS_PASS is missing from .env"
        )

    if QUALYS_CA_BUNDLE:
        if not Path(QUALYS_CA_BUNDLE).is_file():
            raise ValueError(
                "QUALYS_CA_BUNDLE file does not exist."
            )

# ============================================================
# LOAD EXCEL
# ============================================================

def load_excel():

    if not EXCEL_FILE.exists():
        raise FileNotFoundError(
            f"Excel file not found: {EXCEL_FILE}"
        )

    df = pd.read_excel(
        EXCEL_FILE,
        dtype=str,
        keep_default_na=False,
    )

    df.columns = [
        str(column).strip().lower()
        for column in df.columns
    ]

    required_columns = {
        "id",
        "title",
        "username",
        "password",
        "type",
    }

    missing = (
        required_columns - set(df.columns)
    )

    if missing:
        raise ValueError(
            "Missing Excel columns: "
            + ", ".join(sorted(missing))
        )

    if df.empty:
        raise ValueError(
            "Excel file contains no records."
        )

    for column in (
        "id",
        "title",
        "username",
        "type",
    ):
        df[column] = (
            df[column]
            .astype(str)
            .str.strip()
        )

    # Preserve password value as supplied in Excel.
    df["password"] = df["password"].astype(str)

    df["type"] = df["type"].str.lower()

    if not df["id"].str.fullmatch(r"\d+").all():
        raise ValueError(
            "Record IDs must contain digits only."
        )

    if df["id"].duplicated().any():
        raise ValueError(
            "Duplicate record IDs found in Excel."
        )

    for column in (
        "title",
        "username",
        "password",
        "type",
    ):
        if (df[column] == "").any():
            raise ValueError(
                f"Blank value found in column {column}."
            )

    return df

# ============================================================
# CREATE SESSION
# ============================================================

def create_session():

    session = requests.Session()

    session.auth = HTTPBasicAuth(
        QUALYS_USER,
        QUALYS_PASS,
    )

    session.headers.update({
        "X-Requested-With": (
            "QualysPasswordUpdateScript"
        ),
        "Accept": "application/xml",
    })

    session.verify = TLS_VERIFY

    session.trust_env = True

    return session

# ============================================================
# SSL PREFLIGHT
# ============================================================

def check_ssl(session):

    logger.info(
        "Checking HTTPS connection to Qualys..."
    )

    try:

        response = session.get(
            QUALYS_URL,
            timeout=TIMEOUT,
            allow_redirects=False,
        )

        logger.info(
            "HTTPS connection established. HTTP %s",
            response.status_code,
        )

        return True, (
            f"HTTPS connection established: "
            f"HTTP {response.status_code}"
        )

    except requests.exceptions.SSLError as exc:

        message = (
            "SSL/TLS error: "
            + " ".join(str(exc).split())
        )

        logger.error(message)

        return False, message

    except requests.Timeout:

        message = (
            "HTTPS connection timed out."
        )

        logger.error(message)

        return False, message

    except requests.RequestException as exc:

        message = (
            f"Network error ({type(exc).__name__}): "
            + " ".join(str(exc).split())
        )

        logger.error(message)

        return False, message

# ============================================================
# RESPONSE PARSER
# ============================================================

def local_tag(tag):

    return tag.rsplit("}", 1)[-1].upper()


def parse_response(response_text, expected_id):

    try:

        root = ET.fromstring(
            response_text
        )

    except ET.ParseError:

        return False, (
            "Qualys response is not valid XML."
        )

    for batch in root.iter():

        if local_tag(batch.tag) != "BATCH":
            continue

        batch_ids = [
            (node.text or "").strip()
            for node in batch.iter()
            if local_tag(node.tag) == "ID"
        ]

        if expected_id not in batch_ids:
            continue

        messages = [
            (node.text or "").strip()
            for node in batch.iter()
            if local_tag(node.tag)
            in {"TEXT", "MESSAGE", "ERRORMESSAGE"}
        ]

        message = "; ".join(
            item for item in messages if item
        )

        if not message:
            return False, (
                "Record ID returned without status message."
            )

        lower_message = message.lower()

        if any(term in lower_message for term in (
            "error",
            "failed",
            "failure",
            "invalid",
            "denied",
            "not updated",
        )):
            return False, message

        if (
            "successfully updated" in lower_message
            or "update successful" in lower_message
        ):
            return True, message

        return False, (
            "Update success not explicitly confirmed: "
            + message
        )

    return False, (
        f"Expected record ID {expected_id} "
        "was not found in the response."
    )

# ============================================================
# UPDATE RECORD
# ============================================================

def update_record(session, record):

    record_type = record["type"].lower()

    if record_type == "unix":

        api_url = QUALYS_URL

    elif record_type == "windows":

        api_url = QUALYS_WINDOWS_URL

    else:

        return (
            "FAILED",
            f"Unsupported record type: {record_type}",
        )

    payload = {
        "action": "update",
        "ids": record["id"],
        "username": record["username"],
        "password": record["password"],
    }

    response = session.post(
        api_url,
        data=payload,
        timeout=TIMEOUT,
    )

    if not response.ok:

        return (
            "FAILED",
            f"HTTP error: {response.status_code}",
        )

    success, message = parse_response(
        response.text,
        record["id"],
    )

    if success:

        return "SUCCESS", message

    return "FAILED", message

# ============================================================
# WRITE CSV REPORT
# ============================================================

def write_csv(results):

    columns = [
        "id",
        "title",
        "username",
        "type",
        "status",
        "message",
    ]

    with CSV_FILE.open(
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
# MAIN
# ============================================================

def main():

    session = None

    results = []

    fatal_error = None

    try:

        validate_config()

        df = load_excel()

        total = len(df)

        supported = int(
            df["type"].isin(
                ["unix", "windows"]
            ).sum()
        )

        unsupported = total - supported

        print("\n" + "=" * 72)

        print(
            "QUALYS AUTHENTICATION PASSWORD UPDATE"
        )

        print("=" * 72)

        print(
            f"Total records in Excel       : {total}"
        )

        print(
            f"Supported records to update  : {supported}"
        )

        print(
            f"Unsupported records to fail  : {unsupported}"
        )

        print(
            f"Log file                     : {LOG_FILE.name}"
        )

        print(
            f"CSV report                   : {CSV_FILE.name}"
        )

        print(
            "\nStarting automatically; no confirmation required."
        )

        logger.info(
            "Total records: %d",
            total,
        )

        logger.info(
            "Supported records: %d",
            supported,
        )

        logger.info(
            "Unsupported records: %d",
            unsupported,
        )

        session = create_session()

        # ----------------------------------------------------
        # SSL CHECK
        # ----------------------------------------------------

        ssl_ok, ssl_message = check_ssl(
            session
        )

        if not ssl_ok:

            for record in df.to_dict(
                orient="records"
            ):

                results.append({
                    "id": record["id"],
                    "title": record["title"],
                    "username": record["username"],
                    "type": record["type"],
                    "status": "FAILED",
                    "message": (
                        "Not attempted due to SSL/network failure: "
                        + ssl_message
                    ),
                })

        else:

            # ------------------------------------------------
            # PROCESS EACH RECORD
            # ------------------------------------------------

            for index, record in enumerate(
                df.to_dict(orient="records"),
                start=1,
            ):

                logger.info(
                    "Processing %d/%d | ID=%s | Title=%s | Type=%s",
                    index,
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

                    status = "FAILED"

                    message = (
                        "SSL/TLS error: "
                        + " ".join(str(exc).split())
                    )

                except requests.Timeout:

                    status = "FAILED"

                    message = (
                        "Request timed out. "
                        "Update outcome is unconfirmed."
                    )

                except requests.RequestException as exc:

                    status = "FAILED"

                    message = (
                        f"Network/request error "
                        f"({type(exc).__name__}): "
                        + " ".join(str(exc).split())
                    )

                except Exception as exc:

                    status = "FAILED"

                    message = (
                        f"Unexpected error: "
                        f"{type(exc).__name__}"
                    )

                    logger.debug(
                        traceback.format_exc()
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

        write_csv(results)

    except Exception as exc:

        fatal_error = (
            f"{type(exc).__name__}: {exc}"
        )

        logger.exception(
            "FATAL ERROR: %s",
            fatal_error,
        )

    finally:

        if session is not None:

            session.close()

    if fatal_error:

        print("\nSCRIPT FAILED")

        print(
            "Reason:",
            fatal_error,
        )

        print(
            "Log file:",
            LOG_FILE,
        )

        sys.exit(1)

    # --------------------------------------------------------
    # FINAL SUMMARY
    # --------------------------------------------------------

    total_count = len(results)

    success_count = sum(
        result["status"] == "SUCCESS"
        for result in results
    )

    failed_count = (
        total_count - success_count
    )

    unsupported_count = sum(
        result["message"].startswith(
            "Unsupported record type"
        )
        for result in results
    )

    print("\n" + "=" * 72)

    print(
        "FINAL EXECUTION SUMMARY"
    )

    print("=" * 72)

    print(
        f"Total records          : {total_count}"
    )

    print(
        f"Successful updates     : {success_count}"
    )

    print(
        f"Failed/unconfirmed     : {failed_count}"
    )

    print(
        f"Unsupported records    : {unsupported_count}"
    )

    print(
        f"Log file               : {LOG_FILE.name}"
    )

    print(
        f"CSV report             : {CSV_FILE.name}"
    )

    # --------------------------------------------------------
    # STRICT SUCCESS CONDITION
    # --------------------------------------------------------

    if (
        total_count > 0
        and success_count == total_count
        and failed_count == 0
    ):

        logger.info(
            "SCRIPT COMPLETED SUCCESSFULLY"
        )

        print(
            "\nSCRIPT COMPLETED SUCCESSFULLY"
        )

        sys.exit(0)

    logger.error(
        "SCRIPT FAILED - "
        "ONE OR MORE RECORDS FAILED OR WERE UNCONFIRMED"
    )

    print(
        "\nSCRIPT FAILED - "
        "ONE OR MORE RECORDS FAILED OR WERE UNCONFIRMED"
    )

    sys.exit(1)


if __name__ == "__main__":

    main()