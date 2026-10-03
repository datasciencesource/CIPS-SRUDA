import base64
import hashlib
import os
import subprocess
import sys
import threading
import time
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


STRATEGY = "S3"


# ==========================================================
# Remote MySQL Configuration
# ==========================================================

REMOTE_DB = "jdbc:mysql://69.175.69.34/sumrachna_hd"
REMOTE_DB_USER = "sumrachna_hd"

REMOTE_DB_PASSWORD = os.getenv(
    "REMOTE_DB_PASSWORD"
)

SOURCE_TABLE = os.getenv(
    "SOURCE_TABLE"
)


# ==========================================================
# HDFS Paths - S3 ONLY
# ==========================================================

HDFS_STAGING = "/security_lab/s3_staging"
HDFS_BUILD = "/security_lab/s3_build"
HDFS_TARGET = "/security_lab/s3"


# ==========================================================
# Integrity + Confidentiality
# ==========================================================

HASH_ALGORITHM = "SHA-256"
GENESIS_HASH = "GENESIS"

ENCRYPTION_ALGORITHM = "AES-256-GCM"

AES_KEY_B64 = os.getenv(
    "S3_AES_KEY_B64"
)


# ==========================================================
# S3 Security Event Logging
# ==========================================================

AUDIT_LOG = os.getenv(
    "S3_AUDIT_LOG",
    "/var/log/cips_sruda_s3_audit.log"
)

RUN_ID = os.getenv(
    "S3_RUN_ID",
    (
        f"S3-{SOURCE_TABLE or 'unknown'}-"
        f"{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    )
)

audit_time_total = 0.0


# ==========================================================
# Experimental Datasets
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
# Validate Environment
# ==========================================================

if not REMOTE_DB_PASSWORD:

    print(
        "ERROR: REMOTE_DB_PASSWORD is not set."
    )

    sys.exit(1)


if not SOURCE_TABLE:

    print(
        "ERROR: SOURCE_TABLE is not set."
    )

    print(
        'Example: export SOURCE_TABLE="table_stock100"'
    )

    sys.exit(1)


if SOURCE_TABLE not in DATASETS:

    print(
        f"ERROR: Invalid SOURCE_TABLE: "
        f"{SOURCE_TABLE}"
    )

    sys.exit(1)


if not AES_KEY_B64:

    print(
        "ERROR: S3_AES_KEY_B64 is not set."
    )

    sys.exit(1)


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

    sys.exit(1)


aesgcm = AESGCM(
    AES_KEY
)


DATASET_SCALE = (
    DATASETS[SOURCE_TABLE]["scale"]
)

EXPECTED_RECORDS = (
    DATASETS[SOURCE_TABLE][
        "expected_records"
    ]
)


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

    start = time.perf_counter()

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

        directory = os.path.dirname(
            AUDIT_LOG
        )


        if directory:

            os.makedirs(
                directory,
                exist_ok=True
            )


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
            f"Unable to write S3 audit log: {exc}"
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


    return (
        idle_total
        + active_total,
        idle_total
    )


def get_memory_percent():

    meminfo = {}


    with open(
        "/proc/meminfo",
        "r"
    ) as f:

        for line in f:

            key, value = line.split(
                ":",
                1
            )

            meminfo[key] = float(
                value.strip()
                .split()[0]
            )


    total = meminfo[
        "MemTotal"
    ]

    available = meminfo[
        "MemAvailable"
    ]


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

            cpu_samples.append(
                (
                    (
                        total_delta
                        - idle_delta
                    )
                    / total_delta
                )
                * 100
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
# HDFS Utilities
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
        result.stdout.splitlines()
    ):

        fields = line.split()


        if not fields:

            continue


        candidate = fields[-1]


        if os.path.basename(
            candidate
        ).startswith(
            "part"
        ):

            files.append(
                candidate
            )


    files.sort()


    if not files:

        raise RuntimeError(
            f"No HDFS part files "
            f"found in {path}"
        )


    return files


# ==========================================================
# Indicator 10 - HDFS Data Availability Check
# ==========================================================

def check_hdfs_availability(
    path
):

    # Check dataset path exists.

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
            "HDFS dataset path does not exist",
            0
        )


    # Check dataset contains part files.

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
            "HDFS dataset cannot be listed",
            0
        )


    part_files = []


    for line in (
        result.stdout.splitlines()
    ):

        fields = line.split()


        if not fields:

            continue


        candidate = fields[-1]


        if os.path.basename(
            candidate
        ).startswith(
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
# Reset S3 Paths
# ==========================================================

def reset_s3_environment():

    print(
        "=" * 72
    )

    print(
        "RESETTING PREVIOUS S3 HDFS DATA"
    )

    print(
        "=" * 72
    )


    hdfs_remove(
        HDFS_TARGET
    )

    hdfs_remove(
        HDFS_STAGING
    )

    hdfs_remove(
        HDFS_BUILD
    )


    print(
        f"Removed previous target  : "
        f"{HDFS_TARGET}"
    )

    print(
        f"Removed previous staging : "
        f"{HDFS_STAGING}"
    )

    print(
        f"Removed previous build   : "
        f"{HDFS_BUILD}"
    )

    print()


# ==========================================================
# SHA-256 Hash Chain
# ==========================================================

def calculate_current_hash(
    previous_hash,
    row_data
):

    value = (
        previous_hash
        + "|"
        + row_data
    )


    return hashlib.sha256(
        value.encode(
            "utf-8"
        )
    ).hexdigest()


# ==========================================================
# AES-256-GCM Encryption
# ==========================================================

def encrypt_protected_row(
    protected_row
):

    nonce = os.urandom(
        12
    )


    ciphertext = aesgcm.encrypt(

        nonce,

        protected_row.encode(
            "utf-8"
        ),

        None
    )


    return base64.b64encode(

        nonce
        + ciphertext

    ).decode(
        "utf-8"
    )


# ==========================================================
# Generate Protected + Encrypted Dataset
# ==========================================================

def generate_encrypted_dataset():

    start = (
        time.perf_counter()
    )


    part_files = (
        get_hdfs_part_files(
            HDFS_STAGING
        )
    )


    hdfs_mkdir(
        HDFS_BUILD
    )


    previous_hash = (
        GENESIS_HASH
    )

    protected_records = 0


    for input_part in part_files:

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


                current_hash = (
                    calculate_current_hash(
                        previous_hash,
                        row_data
                    )
                )


                protected_row = (

                    f"{row_data},"

                    f"{previous_hash},"

                    f"{current_hash}"
                )


                encrypted_row = (
                    encrypt_protected_row(
                        protected_row
                    )
                )


                writer.stdin.write(
                    encrypted_row
                    + "\n"
                )


                previous_hash = (
                    current_hash
                )

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

                "Failed reading "
                "HDFS staging data:\n"

                + reader_error
            )


        if writer_returncode != 0:

            raise RuntimeError(

                "Failed writing "
                "encrypted S3 data:\n"

                + writer_error
            )


    if (
        protected_records
        != EXPECTED_RECORDS
    ):

        raise RuntimeError(

            "Protected/encrypted "
            "record-count mismatch: "

            f"expected "
            f"{EXPECTED_RECORDS}, "

            f"generated "
            f"{protected_records}."
        )


    move_result = subprocess.run(

        [
            "hdfs",
            "dfs",
            "-mv",

            HDFS_BUILD,

            HDFS_TARGET
        ]
    )


    if move_result.returncode != 0:

        raise RuntimeError(

            "Unable to activate final "
            "S3 encrypted dataset."
        )


    return (

        protected_records,

        previous_hash,

        (
            time.perf_counter()
            - start
        )
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
    "S3 - PROTECTED SQOOP INGESTION"
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
    f"Final HDFS target     : "
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
# Preparation
# ==========================================================

reset_s3_environment()


monitor_thread = threading.Thread(

    target=monitor_resources,

    daemon=True
)

monitor_thread.start()


sqoop_returncode = 1

security_status = (
    "NOT RUN"
)

protected_records = 0

final_chain_hash = "N/A"

hash_encrypt_time = 0.0

hdfs_availability_time = 0.0

hdfs_availability_status = (
    "NOT RUN"
)

hdfs_availability_reason = (
    "N/A"
)

hdfs_part_count = 0


try:

    audit_event(

        "SCRIPT1_START",

        "STARTED",

        "N/A",

        "N/A",

        f"source_table={SOURCE_TABLE}"
    )


    # ======================================================
    # Stage 1 - Sqoop
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
    # Stage 2 - Hash + Encryption
    # ======================================================

    print()

    print(
        "=" * 72
    )

    print(
        "STAGE 2 - SHA-256 HASH CHAIN "
        "+ AES-256-GCM ENCRYPTION"
    )

    print(
        "=" * 72
    )


    (
        protected_records,
        final_chain_hash,
        hash_encrypt_time
    ) = (
        generate_encrypted_dataset()
    )


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
    # Stage 3 - Indicator 10
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


    check_start = (
        time.perf_counter()
    )


    (
        available,
        reason,
        part_count
    ) = (
        check_hdfs_availability(
            HDFS_TARGET
        )
    )


    hdfs_availability_time = (

        time.perf_counter()

        - check_start
    )


    hdfs_availability_reason = (
        reason
    )

    hdfs_part_count = (
        part_count
    )


    if not available:

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


        raise RuntimeError(
            reason
        )


    hdfs_availability_status = (
        "PASS"
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


    security_status = (
        "SUCCESS"
    )


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


    except Exception as log_exc:

        print(
            f"AUDIT ERROR: "
            f"{log_exc}"
        )


    hdfs_remove(
        HDFS_TARGET
    )

    hdfs_remove(
        HDFS_BUILD
    )


finally:

    hdfs_remove(
        HDFS_STAGING
    )


# ==========================================================
# Stop Monitoring
# ==========================================================

stop_monitoring.set()

monitor_thread.join()


average_cpu = (

    sum(cpu_samples)
    / len(cpu_samples)

    if cpu_samples

    else 0.0
)


peak_cpu = (

    max(cpu_samples)

    if cpu_samples

    else 0.0
)


average_memory = (

    sum(memory_samples)
    / len(memory_samples)

    if memory_samples

    else 0.0
)


peak_memory = (

    max(memory_samples)

    if memory_samples

    else 0.0
)


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


hdfs_size_bytes = (

    get_hdfs_size_bytes(
        HDFS_TARGET
    )

    if security_status
    == "SUCCESS"

    else 0
)


hdfs_size_mb = (

    hdfs_size_bytes

    / (1024 ** 2)
)


additional_security_processing_time = (

    hash_encrypt_time

    + hdfs_availability_time

    + audit_time_total
)


script1_total_measured_time = (

    (
        sqoop_ingestion_time

        if "sqoop_ingestion_time"
        in globals()

        else 0.0
    )

    + additional_security_processing_time
)


execution_status = (

    "SUCCESS"

    if (

        sqoop_returncode == 0

        and security_status
        == "SUCCESS"

        and protected_records
        == EXPECTED_RECORDS

        and hdfs_availability_status
        == "PASS"
    )

    else "FAILED"
)


final_returncode = (

    0

    if execution_status
    == "SUCCESS"

    else 1
)


# ==========================================================
# Results
# ==========================================================

print()

print(
    "=" * 72
)

print(
    "S3 - SQOOP + PROTECTION "
    "+ HDFS AVAILABILITY RESULT"
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
    f"{hdfs_availability_status}"
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


print(
    f"Sqoop ingestion time                  : "
    f"{(
        sqoop_ingestion_time
        if 'sqoop_ingestion_time'
        in globals()
        else 0.0
    ):.2f} seconds"
)

print(
    f"Hash-chain + encryption time          : "
    f"{hash_encrypt_time:.2f} seconds"
)

print(
    f"HDFS availability-check time          : "
    f"{hdfs_availability_time:.4f} seconds"
)

print(
    f"Audit logging time                    : "
    f"{audit_time_total:.4f} seconds"
)

print(
    f"Additional security-processing time   : "
    f"{additional_security_processing_time:.2f} seconds"
)

print(
    f"Script 1 total measured time          : "
    f"{script1_total_measured_time:.2f} seconds"
)


print()


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
    f"Audit log                             : "
    f"{AUDIT_LOG}"
)

print(
    "=" * 72
)


sys.exit(
    final_returncode
)
