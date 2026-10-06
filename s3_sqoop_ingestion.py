import base64
import hashlib
import os
import subprocess
import sys
import threading
import time
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ==========================================================
# S3 - PROTECTED SQOOP INGESTION
# ==========================================================
#
# IMPORTANT:
# /security_lab/s3 is MANUALLY managed.
#
# This script:
#   - DOES NOT create /security_lab/s3
#   - DOES NOT delete /security_lab/s3
#   - CREATES the audit log if it does not exist
#   - APPENDS to the audit log if it already exists
#
# Before a normal run:
#
#   hdfs dfs -rm -r -f /security_lab/s3
#   hdfs dfs -mkdir -p /security_lab/s3
#
# Pipeline:
#
# Remote MySQL
#   -> Sqoop
#   -> /security_lab/s3_staging
#   -> SHA-256 hash-chain generation
#   -> AES-256-GCM encryption
#   -> /security_lab/s3_build/part*
#   -> move encrypted part files only
#   -> /security_lab/s3/part*
#   -> S2 processing: SHA-256 hash-chain + AES-256-GCM encryption
#   -> S3 control: HDFS Data Availability Check
#   -> S3 control: Audit Logging
#
# ==========================================================


STRATEGY = "S3"

# This version is intentionally S3-only.
ENABLE_INTEGRITY = True
ENABLE_ENCRYPTION = True
ENABLE_AVAILABILITY = True
ENABLE_AUDIT = True


# ==========================================================
# Remote MySQL Configuration
# ==========================================================

REMOTE_DB = (
    "jdbc:mysql://69.175.69.34/"
    "sumrachna_hd"
)

REMOTE_DB_USER = "sumrachna_hd"

REMOTE_DB_PASSWORD = os.getenv(
    "REMOTE_DB_PASSWORD"
)

SOURCE_TABLE = os.getenv(
    "SOURCE_TABLE"
)


# ==========================================================
# HDFS Paths - selected strategy
# ==========================================================

HDFS_STAGING = "/security_lab/s3_staging"

HDFS_BUILD = "/security_lab/s3_build"

HDFS_TARGET = "/security_lab/s3"


# ==========================================================
# Integrity + Confidentiality Configuration
# ==========================================================

HASH_ALGORITHM = "SHA-256"

GENESIS_HASH = "GENESIS"

ENCRYPTION_ALGORITHM = (
    "AES-256-GCM"
)

AES_KEY_B64 = os.getenv("S3_AES_KEY_B64")


# ==========================================================
# Indicator 12 - Security Event Logging
# ==========================================================

AUDIT_LOG = os.getenv(
    "S3_AUDIT_LOG",
    "/var/log/cips_sruda_s3_audit.log"
)


RUN_ID = os.getenv(
    "S3_RUN_ID",
    (
        f"{STRATEGY}-"
        f"{SOURCE_TABLE or 'unknown'}-"
        f"{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    )
)


audit_time_total = 0.0


# ==========================================================
# Experimental Dataset Definition
# ==========================================================

DATASETS = {

    "table_stock100": {
        "scale": "Small",
        "expected_records": 125
    },

    "table_stock20K": {
        "scale": "Medium",
        "expected_records": 24858
    },

    "table_stock4M": {
        "scale": "Large",
        "expected_records": 4248576
    }
}


# ==========================================================
# Validate Environment Variables
# ==========================================================

if not REMOTE_DB_PASSWORD:

    print(
        "ERROR: REMOTE_DB_PASSWORD "
        "is not set."
    )

    print(
        "Example:"
    )

    print(
        "export REMOTE_DB_PASSWORD="
        "'your_password'"
    )

    sys.exit(1)


if not SOURCE_TABLE:

    print(
        "ERROR: SOURCE_TABLE is not set."
    )

    print(
        "Choose one:"
    )

    print(
        'export SOURCE_TABLE="table_stock100"'
    )

    print(
        'export SOURCE_TABLE="table_stock20K"'
    )

    print(
        'export SOURCE_TABLE="table_stock4M"'
    )

    sys.exit(1)


if SOURCE_TABLE not in DATASETS:

    print(
        f"ERROR: Invalid SOURCE_TABLE: "
        f"{SOURCE_TABLE}"
    )

    print(
        "Allowed experimental tables:"
    )

    print(
        "  table_stock100 = Small"
    )

    print(
        "  table_stock20K = Medium"
    )

    print(
        "  table_stock4M  = Large"
    )

    sys.exit(1)


if ENABLE_ENCRYPTION and not AES_KEY_B64:

    print(
        "ERROR: S3_AES_KEY_B64 "
        "is not set."
    )

    print(
        'export S3_AES_KEY_B64="'
        '<your-base64-encoded-32-byte-key>"'
    )

    sys.exit(1)


if ENABLE_ENCRYPTION:
    try:

        AES_KEY = base64.b64decode(
            AES_KEY_B64,
            validate=True
        )

    except Exception:

        print(
            "ERROR: S3_AES_KEY_B64 "
            "is not valid Base64."
        )

        sys.exit(1)


    if len(AES_KEY) != 32:

        print(
            "ERROR: AES-256 requires exactly "
            "32 decoded key bytes."
        )

        print(
            f"Decoded key length: "
            f"{len(AES_KEY)} bytes"
        )

        sys.exit(1)


    aesgcm = AESGCM(AES_KEY)
else:
    AES_KEY = b""
    aesgcm = None


DATASET_SCALE = (
    DATASETS[
        SOURCE_TABLE
    ]["scale"]
)


EXPECTED_RECORDS = (
    DATASETS[
        SOURCE_TABLE
    ]["expected_records"]
)


# ==========================================================
# Audit Log Initialization
# ==========================================================

def initialize_audit_log():
    """
    Create the S3 audit log if it does not exist.

    If the log already exists, preserve its existing
    contents. Later audit_event() calls append new records.
    """

    directory = (
        os.path.dirname(
            AUDIT_LOG
        )
    )


    if directory:

        os.makedirs(
            directory,
            exist_ok=True
        )


    # Append mode:
    #
    # Missing file -> create
    # Existing file -> preserve
    #
    with open(
        AUDIT_LOG,
        "a",
        encoding="utf-8"
    ):
        pass


# ==========================================================
# Indicator 12 - Security Event Logging
# ==========================================================

def audit_event(
    event,
    status,
    decision="N/A",
    reason="N/A",
    details="N/A"
):

    global audit_time_total

    if not ENABLE_AUDIT:
        return


    start = (
        time.perf_counter()
    )


    timestamp = (
        datetime.now()
        .astimezone()
        .isoformat(
            timespec="seconds"
        )
    )


    line = (

        f"{timestamp}"

        f"\tRUN_ID={RUN_ID}"

        f"\tSTRATEGY={STRATEGY}"

        f"\tEVENT={event}"

        f"\tSTATUS={status}"

        f"\tDECISION={decision}"

        f"\tREASON={reason}"

        f"\tDETAILS={details}"

        "\n"
    )


    try:

        directory = (
            os.path.dirname(
                AUDIT_LOG
            )
        )


        if directory:

            os.makedirs(
                directory,
                exist_ok=True
            )


        # "a" means:
        #
        # create when missing
        # append when existing
        #
        with open(
            AUDIT_LOG,
            "a",
            encoding="utf-8"
        ) as log_file:

            log_file.write(
                line
            )


    except Exception as exc:

        raise RuntimeError(
            "Unable to write "
            f"S3 audit log: {exc}"
        ) from exc


    finally:

        audit_time_total += (
            time.perf_counter()
            - start
        )


# ==========================================================
# Resource Monitoring
# ==========================================================

cpu_samples = []

memory_samples = []

stop_monitoring = (
    threading.Event()
)


def get_cpu_values():

    with open(
        "/proc/stat",
        "r"
    ) as f:

        values = list(
            map(
                float,
                f.readline()
                .split()[1:9]
            )
        )


    (
        user,
        nice,
        system,
        idle,
        iowait,
        irq,
        softirq,
        steal
    ) = values


    idle_total = (
        idle
        + iowait
    )


    active_total = (
        user
        + nice
        + system
        + irq
        + softirq
        + steal
    )


    total = (
        idle_total
        + active_total
    )


    return (
        total,
        idle_total
    )


def get_memory_percent():

    meminfo = {}


    with open(
        "/proc/meminfo",
        "r"
    ) as f:

        for line in f:

            key, value = (
                line.split(
                    ":",
                    1
                )
            )


            meminfo[key] = float(
                value.strip()
                .split()[0]
            )


    total = (
        meminfo[
            "MemTotal"
        ]
    )


    available = (
        meminfo[
            "MemAvailable"
        ]
    )


    return (
        (
            total
            - available
        )
        / total
    ) * 100


def monitor_resources():

    (
        previous_total,
        previous_idle
    ) = get_cpu_values()


    while not stop_monitoring.wait(
        0.5
    ):

        (
            current_total,
            current_idle
        ) = get_cpu_values()


        total_delta = (
            current_total
            - previous_total
        )


        idle_delta = (
            current_idle
            - previous_idle
        )


        if total_delta > 0:

            cpu_percent = (

                (
                    total_delta
                    - idle_delta
                )

                / total_delta

            ) * 100


            cpu_samples.append(
                cpu_percent
            )


        memory_samples.append(
            get_memory_percent()
        )


        previous_total = (
            current_total
        )

        previous_idle = (
            current_idle
        )


# ==========================================================
# HDFS Utility Functions
# ==========================================================

def hdfs_remove(
    path
):

    subprocess.run(
        [
            "hdfs",
            "dfs",
            "-rm",
            "-r",
            "-f",
            path
        ],

        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def hdfs_mkdir(
    path
):

    subprocess.run(
        [
            "hdfs",
            "dfs",
            "-mkdir",
            "-p",
            path
        ],

        check=True
    )


def get_hdfs_size_bytes(
    path
):

    result = subprocess.run(
        [
            "hdfs",
            "dfs",
            "-du",
            "-s",
            path
        ],

        capture_output=True,
        text=True
    )


    if result.returncode != 0:

        return 0


    try:

        return int(
            result.stdout
            .split()[0]
        )


    except (
        ValueError,
        IndexError
    ):

        return 0


def get_hdfs_part_files(
    path
):

    result = subprocess.run(
        [
            "hdfs",
            "dfs",
            "-ls",
            path
        ],

        capture_output=True,
        text=True
    )


    if result.returncode != 0:

        raise RuntimeError(
            f"Unable to list "
            f"HDFS path: {path}"
        )


    files = []


    for line in (
        result.stdout
        .splitlines()
    ):

        fields = (
            line.split()
        )


        if not fields:

            continue


        candidate = (
            fields[-1]
        )


        basename = (
            os.path.basename(
                candidate
            )
        )


        if basename.startswith(
            "part"
        ):

            files.append(
                candidate
            )


    # Deterministic ordering is required
    # for the sequential hash chain.

    files.sort()


    if not files:

        raise RuntimeError(
            f"No HDFS part files "
            f"found in {path}"
        )


    return files


# ==========================================================
# Manual S3 Target Validation
# ==========================================================

def validate_manual_s3_target(
    path
):

    # ------------------------------------------------------
    # Check that /security_lab/s3 exists
    # ------------------------------------------------------

    result = subprocess.run(
        [
            "hdfs",
            "dfs",
            "-test",
            "-e",
            path
        ]
    )


    if result.returncode != 0:

        raise RuntimeError(
            "S3 HDFS target "
            f"does not exist: {path}"
        )


    # ------------------------------------------------------
    # Check that it is a directory
    # ------------------------------------------------------

    result = subprocess.run(
        [
            "hdfs",
            "dfs",
            "-test",
            "-d",
            path
        ]
    )


    if result.returncode != 0:

        raise RuntimeError(
            "S3 HDFS target "
            f"is not a directory: {path}"
        )


    # ------------------------------------------------------
    # Check that it is accessible and EMPTY
    # ------------------------------------------------------

    result = subprocess.run(
        [
            "hdfs",
            "dfs",
            "-ls",
            path
        ],

        capture_output=True,
        text=True
    )


    if result.returncode != 0:

        raise RuntimeError(
            "Unable to access "
            f"manual S3 target: {path}"
        )


    existing_files = []


    for line in (
        result.stdout
        .splitlines()
    ):

        line = (
            line.strip()
        )


        if not line:

            continue


        if line.startswith(
            "Found "
        ):

            continue


        fields = (
            line.split()
        )


        if fields:

            existing_files.append(
                fields[-1]
            )


    if existing_files:

        raise RuntimeError(
            "S3 HDFS target "
            "must be empty before the run: "
            f"{path}"
        )


    return True


# ==========================================================
# Indicator 10
# HDFS Data Availability Check
# ==========================================================

def check_hdfs_availability(
    path
):

    # ------------------------------------------------------
    # Check dataset path exists
    # ------------------------------------------------------

    result = subprocess.run(
        [
            "hdfs",
            "dfs",
            "-test",
            "-e",
            path
        ]
    )


    if result.returncode != 0:

        return (
            False,
            "HDFS dataset path "
            "does not exist",
            0
        )


    # ------------------------------------------------------
    # Check dataset can be listed
    # ------------------------------------------------------

    result = subprocess.run(
        [
            "hdfs",
            "dfs",
            "-ls",
            path
        ],

        capture_output=True,
        text=True
    )


    if result.returncode != 0:

        return (
            False,
            "HDFS dataset "
            "cannot be listed",
            0
        )


    # ------------------------------------------------------
    # Check dataset contains part files
    # ------------------------------------------------------

    part_files = []


    for line in (
        result.stdout
        .splitlines()
    ):

        fields = (
            line.split()
        )


        if not fields:

            continue


        candidate = (
            fields[-1]
        )


        basename = (
            os.path.basename(
                candidate
            )
        )


        if basename.startswith(
            "part"
        ):

            part_files.append(
                candidate
            )


    if not part_files:

        return (
            False,
            "No HDFS part files found",
            0
        )


    return (
        True,
        "HDFS dataset available",
        len(part_files)
    )


# ==========================================================
# Reset TEMPORARY S3 Paths Only
# ==========================================================

def reset_s3_environment():

    print(
        "=" * 72
    )

    print(
        "RESETTING TEMPORARY S3 HDFS DATA"
    )

    print(
        "=" * 72
    )


    # IMPORTANT:
    #
    # Do NOT remove /security_lab/s3.

    hdfs_remove(
        HDFS_STAGING
    )


    hdfs_remove(
        HDFS_BUILD
    )

    if STRATEGY != "S3":
        hdfs_remove(HDFS_TARGET)
        hdfs_mkdir(HDFS_TARGET)


    print(
        f"Manual target preserved   : "
        f"{HDFS_TARGET}"
    )


    print(
        f"Removed previous staging  : "
        f"{HDFS_STAGING}"
    )


    print(
        f"Removed previous build    : "
        f"{HDFS_BUILD}"
    )


    print()


# ==========================================================
# SHA-256 Hash-Chain Function
# ==========================================================

def calculate_current_hash(
    previous_hash,
    row_data
):

    hash_input = (
        previous_hash
        + "|"
        + row_data
    )


    return hashlib.sha256(
        hash_input.encode(
            "utf-8"
        )
    ).hexdigest()


# ==========================================================
# AES-256-GCM Encryption Function
# ==========================================================

def encrypt_protected_row(
    protected_row
):

    if not ENABLE_ENCRYPTION:
        return protected_row

    nonce = os.urandom(
        12
    )


    ciphertext = (
        aesgcm.encrypt(
            nonce,
            protected_row.encode(
                "utf-8"
            ),
            None
        )
    )


    encrypted_bytes = (
        nonce
        + ciphertext
    )


    return base64.b64encode(
        encrypted_bytes
    ).decode(
        "utf-8"
    )


# ==========================================================
# Generate Protected + Encrypted S3 Dataset
# ==========================================================

def generate_encrypted_dataset():

    security_start = (
        time.perf_counter()
    )


    part_files = (
        get_hdfs_part_files(
            HDFS_STAGING
        )
    )


    # Temporary build directory only.

    hdfs_mkdir(
        HDFS_BUILD
    )


    previous_hash = (
        GENESIS_HASH
    )


    protected_records = 0


    # ------------------------------------------------------
    # Process each Sqoop part file
    # ------------------------------------------------------

    for input_part in (
        part_files
    ):

        part_name = (
            os.path.basename(
                input_part
            )
        )


        output_part = (
            f"{HDFS_BUILD}/"
            f"{part_name}"
        )


        print(
            f"Hashing + encrypting: "
            f"{part_name}"
        )


        reader = subprocess.Popen(
            [
                "hdfs",
                "dfs",
                "-cat",
                input_part
            ],

            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )


        writer = subprocess.Popen(
            [
                "hdfs",
                "dfs",
                "-put",
                "-",
                output_part
            ],

            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )


        try:

            for raw_line in (
                reader.stdout
            ):

                row_data = (
                    raw_line.rstrip(
                        "\r\n"
                    )
                )


                if not row_data:

                    continue


                if ENABLE_INTEGRITY:
                    current_hash = calculate_current_hash(
                        previous_hash,
                        row_data
                    )

                    protected_row = (
                        f"{row_data},"
                        f"{previous_hash},"
                        f"{current_hash}"
                    )
                else:
                    current_hash = previous_hash
                    protected_row = row_data


                encrypted_row = (
                    encrypt_protected_row(
                        protected_row
                    )
                )


                # ==========================================
                # Write encrypted record
                # ==========================================

                writer.stdin.write(
                    encrypted_row
                    + "\n"
                )


                if ENABLE_INTEGRITY:
                    previous_hash = current_hash


                protected_records += 1


        finally:

            if reader.stdout:

                reader.stdout.close()


            if writer.stdin:

                writer.stdin.close()


        reader_error = (
            reader.stderr.read()
            if reader.stderr
            else ""
        )


        writer_error = (
            writer.stderr.read()
            if writer.stderr
            else ""
        )


        reader_returncode = (
            reader.wait()
        )


        writer_returncode = (
            writer.wait()
        )


        if reader_returncode != 0:

            raise RuntimeError(
                "Failed to read HDFS "
                "staging file:\n"
                + reader_error
            )


        if writer_returncode != 0:

            raise RuntimeError(
                "Failed to write "
                "encrypted HDFS file:\n"
                + writer_error
            )


    # ======================================================
    # Verify Record Count
    # ======================================================

    if (
        protected_records
        != EXPECTED_RECORDS
    ):

        raise RuntimeError(
            "Protected/encrypted "
            "record-count mismatch: "
            f"expected {EXPECTED_RECORDS}, "
            f"generated {protected_records}."
        )


    # ======================================================
    # Move encrypted part files into MANUAL target
    # ======================================================

    build_part_files = (
        get_hdfs_part_files(
            HDFS_BUILD
        )
    )


    for build_part in (
        build_part_files
    ):

        move_result = (
            subprocess.run(
                [
                    "hdfs",
                    "dfs",
                    "-mv",
                    build_part,
                    HDFS_TARGET
                ],

                capture_output=True,
                text=True
            )
        )


        if move_result.returncode != 0:

            raise RuntimeError(
                "Unable to move encrypted "
                "part file into manually "
                "created S3 target:\n"
                + move_result.stderr
            )


    # Remove temporary build directory.

    hdfs_remove(
        HDFS_BUILD
    )


    security_end = (
        time.perf_counter()
    )


    security_processing_time = (
        security_end
        - security_start
    )


    return (
        protected_records,
        previous_hash,
        security_processing_time
    )


# ==========================================================
# Sqoop Command
# ==========================================================

sqoop_command = [

    "sqoop",
    "import",

    "--connect",
    REMOTE_DB,

    "--username",
    REMOTE_DB_USER,

    "--password",
    REMOTE_DB_PASSWORD,

    "--table",
    SOURCE_TABLE,

    "--target-dir",
    HDFS_STAGING,

    "--delete-target-dir"
]


# ==========================================================
# Experiment Header
# ==========================================================

print(
    "=" * 72
)


print(
    f"{STRATEGY} - CUMULATIVE SQOOP INGESTION"
)


print(
    "=" * 72
)


print(
    f"Strategy              : "
    f"{STRATEGY}"
)


print(
    f"Dataset scale         : "
    f"{DATASET_SCALE}"
)


print(
    f"Source table          : "
    f"{SOURCE_TABLE}"
)


print(
    f"Expected records      : "
    f"{EXPECTED_RECORDS}"
)


print(
    f"Manual HDFS target    : "
    f"{HDFS_TARGET}"
)


print(
    f"Hash algorithm        : "
    f"{HASH_ALGORITHM}"
)


print(
    f"Encryption algorithm  : "
    f"{ENCRYPTION_ALGORITHM}"
)


print(
    f"AES key length        : "
    f"{len(AES_KEY) * 8} bits"
)


print(
    f"Audit log             : "
    f"{AUDIT_LOG}"
)


print(
    f"Run ID                : "
    f"{RUN_ID}"
)


print()


# ==========================================================
# PREPARATION
#
# Not included in experimental performance timing.
# ==========================================================

# ----------------------------------------------------------
# Initialize audit log BEFORE HDFS validation.
#
# Missing file:
#     create
#
# Existing file:
#     preserve and append
# ----------------------------------------------------------

try:

    initialize_audit_log()


except Exception as exc:

    print(
        "ERROR: Unable to initialize "
        f"S3 audit log: {exc}"
    )

    sys.exit(1)


reset_s3_environment()


print(
    "=" * 72
)


print(
    "VALIDATING MANUAL S3 HDFS TARGET"
)


print(
    "=" * 72
)


try:

    if STRATEGY == "S3":
        validate_manual_s3_target(HDFS_TARGET)
    else:
        hdfs_mkdir(HDFS_TARGET)


    print(
        f"Manual HDFS target     : "
        f"{HDFS_TARGET}"
    )


    print(
        "Target status          : READY"
    )


    print(
        "Target contents        : EMPTY"
    )


    print(
        "Target creation        : "
        + ("MANUAL" if STRATEGY == "S3" else "SCRIPT-MANAGED")
    )


    print()


except Exception as exc:

    # ------------------------------------------------------
    # The audit file already exists now.
    #
    # Record the HDFS target validation failure.
    # ------------------------------------------------------

    try:

        audit_event(
            "HDFS_TARGET_VALIDATION",
            "FAIL",
            "BLOCK",
            "HDFS_TARGET_INVALID",
            (
                str(exc)
                .replace(
                    "\t",
                    " "
                )
                .replace(
                    "\n",
                    " "
                )
            )
        )


    except Exception as log_exc:

        print(
            "AUDIT ERROR: "
            f"{log_exc}"
        )


    print()


    print(
        f"ERROR: {exc}"
    )


    print()


    print(
        "Create an EMPTY S3 HDFS "
        "target manually before "
        "running this script:"
    )


    print()


    print(
        "hdfs dfs -rm -r -f "
        "/security_lab/s3"
    )


    print(
        "hdfs dfs -mkdir -p "
        "/security_lab/s3"
    )


    print()


    print(
        "The script did NOT create "
        "/security_lab/s3."
    )


    print(
        f"Failure recorded in audit log: "
        f"{AUDIT_LOG}"
    )


    sys.exit(1)


# ==========================================================
# Start Resource Monitoring
# ==========================================================

monitor_thread = (
    threading.Thread(
        target=monitor_resources,
        daemon=True
    )
)


monitor_thread.start()


# ==========================================================
# Result Variables
# ==========================================================

sqoop_returncode = 1

sqoop_ingestion_time = 0.0

security_status = (
    "NOT RUN"
)

protected_records = 0

final_chain_hash = (
    "N/A"
)

hash_encrypt_time = 0.0

hdfs_availability_time = 0.0

hdfs_availability_status = (
    "NOT RUN"
)

hdfs_availability_reason = (
    "N/A"
)

hdfs_part_count = 0


# ==========================================================
# Experimental Execution
# ==========================================================

try:

    # ======================================================
    # Indicator 12
    # Log Script Start
    # ======================================================

    audit_event(
        "SCRIPT1_START",
        "STARTED",
        "N/A",
        "N/A",
        (
            f"source_table="
            f"{SOURCE_TABLE}"
        )
    )


    # ======================================================
    # STAGE 1 - SQOOP INGESTION
    # ======================================================

    print(
        "=" * 72
    )


    print(
        "STAGE 1 - SQOOP INGESTION"
    )


    print(
        "=" * 72
    )


    sqoop_start = (
        time.perf_counter()
    )


    sqoop_result = (
        subprocess.run(
            sqoop_command
        )
    )


    sqoop_end = (
        time.perf_counter()
    )


    sqoop_ingestion_time = (
        sqoop_end
        - sqoop_start
    )


    sqoop_returncode = (
        sqoop_result.returncode
    )


    if sqoop_returncode != 0:

        audit_event(
            "SQOOP_INGESTION",
            "FAIL",
            "BLOCK",
            "SQOOP_FAILURE",
            (
                f"source_table="
                f"{SOURCE_TABLE}"
            )
        )


        raise RuntimeError(
            "Sqoop ingestion failed."
        )


    audit_event(
        "SQOOP_INGESTION",
        "SUCCESS",
        "ALLOW",
        "N/A",
        (
            f"source_table="
            f"{SOURCE_TABLE}"
        )
    )


    # ======================================================
    # STAGE 2
    # SHA-256 + AES-256-GCM
    # ======================================================

    print()


    print(
        "=" * 72
    )


    print(
        "STAGE 2 - CUMULATIVE INTEGRITY "
        "+ CONFIDENTIALITY PROCESSING"
    )


    print(
        "=" * 72
    )


    (
        protected_records,
        final_chain_hash,
        hash_encrypt_time
    ) = generate_encrypted_dataset()


    audit_event(
        "INTEGRITY_CONFIDENTIALITY_PROTECTION",
        "SUCCESS",
        "ALLOW",
        "N/A",
        (
            f"records="
            f"{protected_records}"
        )
    )


    # ======================================================
    # STAGE 3
    # Indicator 10
    # HDFS Data Availability Check
    # ======================================================

    print()


    print(
        "=" * 72
    )


    print(
        "STAGE 3 - HDFS DATA "
        "AVAILABILITY CHECK"
    )


    print(
        "=" * 72
    )


    if ENABLE_AVAILABILITY:
        check_start = time.perf_counter()

        (
            available,
            reason,
            part_count
        ) = check_hdfs_availability(HDFS_TARGET)

        hdfs_availability_time = (
            time.perf_counter() - check_start
        )
    else:
        available = True
        reason = "Not applicable for " + STRATEGY
        part_count = 0
        hdfs_availability_time = 0.0


    hdfs_availability_reason = (
        reason
    )


    hdfs_part_count = (
        part_count
    )


    if ENABLE_AVAILABILITY and not available:

        hdfs_availability_status = (
            "FAIL"
        )


        audit_event(
            "HDFS_AVAILABILITY",
            "FAIL",
            "BLOCK",
            "HDFS_DATASET_UNAVAILABLE",
            reason
        )


        print(
            "HDFS availability     : FAIL"
        )


        print(
            f"Reason                : "
            f"{reason}"
        )


        print(
            "Pipeline decision     : BLOCK"
        )


        raise RuntimeError(
            reason
        )


    hdfs_availability_status = (
        "PASS"
    )


    print(
        "HDFS availability     : "
        + ("PASS" if ENABLE_AVAILABILITY else "NOT RUN")
    )


    print(
        "HDFS availability reason: "
        f"{reason}"
    )


    print(
        f"HDFS part files       : "
        f"{part_count}"
    )


    print(
        "Pipeline decision     : "
        + ("CONTINUE" if ENABLE_AVAILABILITY else "NOT APPLICABLE")
    )


    audit_event(
        "HDFS_AVAILABILITY",
        "PASS",
        "ALLOW",
        "N/A",
        (
            f"part_files="
            f"{part_count}"
        )
    )


    security_status = "SUCCESS"


# ==========================================================
# Failure Handler
# ==========================================================

except Exception as exc:

    security_status = (
        "FAILED"
    )


    print()


    print(
        f"ERROR: {exc}"
    )


    try:

        audit_event(
            "SCRIPT1_END",
            "FAIL",
            "BLOCK",
            "SCRIPT1_FAILURE",
            (
                str(exc)
                .replace(
                    "\t",
                    " "
                )
                .replace(
                    "\n",
                    " "
                )
            )
        )


    except Exception as log_exc:

        print(
            "AUDIT ERROR: "
            f"{log_exc}"
        )


    # IMPORTANT:
    #
    # Do NOT delete /security_lab/s3.
    #
    # Only temporary build data is removed.

    hdfs_remove(
        HDFS_BUILD
    )


finally:

    # Raw plaintext staging is always removed.

    hdfs_remove(
        HDFS_STAGING
    )


# ==========================================================
# Stop Resource Monitoring
# ==========================================================

stop_monitoring.set()


monitor_thread.join()


# ==========================================================
# Resource Results
# ==========================================================

average_cpu = (

    sum(
        cpu_samples
    )

    / len(
        cpu_samples
    )

    if cpu_samples

    else 0.0
)


peak_cpu = (

    max(
        cpu_samples
    )

    if cpu_samples

    else 0.0
)


average_memory = (

    sum(
        memory_samples
    )

    / len(
        memory_samples
    )

    if memory_samples

    else 0.0
)


peak_memory = (

    max(
        memory_samples
    )

    if memory_samples

    else 0.0
)


# ==========================================================
# Final Success Audit Event
# ==========================================================

if security_status == "SUCCESS":

    try:

        audit_event(
            "SCRIPT1_END",
            "SUCCESS",
            "ALLOW",
            "N/A",
            (
                f"records="
                f"{protected_records}"
            )
        )


    except Exception as exc:

        print(
            f"AUDIT ERROR: {exc}"
        )


        security_status = (
            "FAILED"
        )


# ==========================================================
# Final HDFS Storage Size
# ==========================================================

hdfs_size_bytes = 0


if security_status == "SUCCESS":

    hdfs_size_bytes = (
        get_hdfs_size_bytes(
            HDFS_TARGET
        )
    )


hdfs_size_mb = (

    hdfs_size_bytes

    / (1024 ** 2)
)


# ==========================================================
# Performance Measurements
# ==========================================================

"""Cumulative S3 Script 1 timing:

S3 Script 1 = S2 Script 1 + S3 HDFS availability check + S3 audit logging.

The S2 component already includes the S1 hash-chain operation. It must not be
added again as a separate value.
"""

s3_script1_control_time = (

    hdfs_availability_time

    + audit_time_total
)


additional_security_processing_time = (

    hash_encrypt_time

    + s3_script1_control_time
)


script1_total_measured_time = (

    sqoop_ingestion_time

    + additional_security_processing_time
)


# ==========================================================
# Final Execution Status
# ==========================================================

if (
    sqoop_returncode == 0

    and security_status
    == "SUCCESS"

    and protected_records
    == EXPECTED_RECORDS

    and (
        not ENABLE_AVAILABILITY
        or hdfs_availability_status == "PASS"
    )
):

    execution_status = (
        "SUCCESS"
    )

    final_returncode = 0


else:

    execution_status = (
        "FAILED"
    )

    final_returncode = 1


# ==========================================================
# Final Results
# ==========================================================

print()


print(
    "=" * 72
)


print(
    f"{STRATEGY} SCRIPT 1 - CUMULATIVE RESULT"
)


print(
    "=" * 72
)


print(
    f"Strategy                              : "
    f"{STRATEGY}"
)


print(
    f"Dataset scale                         : "
    f"{DATASET_SCALE}"
)


print(
    f"Source table                          : "
    f"{SOURCE_TABLE}"
)


print(
    f"Expected records                      : "
    f"{EXPECTED_RECORDS}"
)


print(
    f"Protected/encrypted records           : "
    f"{protected_records}"
)


print(
    f"Execution status                      : "
    f"{execution_status}"
)


print(
    f"Security-protection status            : "
    f"{security_status}"
)


print(
    f"HDFS availability                     : "
    f"{hdfs_availability_status if ENABLE_AVAILABILITY else 'NOT APPLICABLE'}"
)


print(
    f"HDFS availability reason              : "
    f"{hdfs_availability_reason}"
)


print(
    f"HDFS part files                       : "
    f"{hdfs_part_count}"
)


print()


# ----------------------------------------------------------
# Timing
# ----------------------------------------------------------

print(
    f"Sqoop ingestion time                  : "
    f"{sqoop_ingestion_time:.2f} seconds"
)


print(
    f"{STRATEGY} integrity/confidentiality time: "
    f"{hash_encrypt_time:.2f} seconds"
)


print(
    f"{STRATEGY} HDFS availability-check time : "
    f"{hdfs_availability_time:.4f} seconds"
)


print(
    f"{STRATEGY} audit logging time            : "
    f"{audit_time_total:.4f} seconds"
)


print(
    f"{STRATEGY} control time                 : "
    f"(availability + audit logging)        : "
    f"{s3_script1_control_time:.4f} seconds"
)


print(
    f"{STRATEGY} cumulative security time      : "
    f"{additional_security_processing_time:.2f} seconds"
)


print(
    f"{STRATEGY} Script 1 total measured time : "
    f"{script1_total_measured_time:.2f} seconds"
)


print()


# ----------------------------------------------------------
# Resource Utilization
# ----------------------------------------------------------

print(
    f"Average CPU utilization               : "
    f"{average_cpu:.2f}%"
)


print(
    f"Peak CPU utilization                  : "
    f"{peak_cpu:.2f}%"
)


print(
    f"Average memory utilization            : "
    f"{average_memory:.2f}%"
)


print(
    f"Peak memory utilization               : "
    f"{peak_memory:.2f}%"
)


print(
    f"HDFS encrypted storage size           : "
    f"{hdfs_size_mb:.4f} MB"
)


print()


# ----------------------------------------------------------
# Security Details
# ----------------------------------------------------------

print(
    f"Hash algorithm                        : "
    f"{HASH_ALGORITHM}"
)


print(
    f"Genesis previous hash                 : "
    f"{GENESIS_HASH}"
)


print(
    f"Final chain hash                      : "
    f"{final_chain_hash}"
)


print(
    f"Encryption algorithm                  : "
    f"{ENCRYPTION_ALGORITHM}"
)


print(
    f"AES key size                          : "
    f"{len(AES_KEY) * 8} bits"
)


print(
    f"Final encrypted dataset               : "
    f"{HDFS_TARGET}/part*"
)


print(
    f"S3 target management                  : "
    f"MANUAL"
)


print(
    f"Audit log                             : "
    f"{AUDIT_LOG}"
)


print(
    "=" * 72
)


# ==========================================================
# Exit
# ==========================================================

sys.exit(
    final_returncode
)
