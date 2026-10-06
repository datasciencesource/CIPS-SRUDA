import base64
import hashlib
import os
import subprocess
import sys
import threading
import time
from datetime import datetime

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pyspark.sql import SparkSession

from pyspark.sql.types import (
    StructField,
    StructType,
    IntegerType,
    DoubleType,
    TimestampType,
    StringType
)

from pyspark.storagelevel import StorageLevel


STRATEGY = "S3"


# ==========================================================
# Dataset Configuration
# ==========================================================

SOURCE_TABLE = os.getenv(
    "SOURCE_TABLE"
)


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


if not SOURCE_TABLE:

    print(
        "ERROR: SOURCE_TABLE is not set."
    )

    sys.exit(1)


if SOURCE_TABLE not in DATASETS:

    print(
        f"ERROR: Invalid SOURCE_TABLE: "
        f"{SOURCE_TABLE}"
    )

    sys.exit(1)


DATASET_SCALE = (
    DATASETS[SOURCE_TABLE]["scale"]
)

EXPECTED_RECORDS = (
    DATASETS[SOURCE_TABLE][
        "expected_records"
    ]
)


# ==========================================================
# HDFS Configuration
# ==========================================================

HDFS_PATH = os.getenv(
    "S3_HDFS_PATH",
    "/security_lab/s3"
)


HDFS_INPUT_PATH = (
    f"hdfs://{HDFS_PATH}/part*"
)


HDFS_DECRYPTED_PATH = (
    "/security_lab/s3_decrypted"
)


HDFS_DECRYPTED_INPUT = (
    "hdfs:///security_lab/"
    "s3_decrypted/part*"
)


# ==========================================================
# Integrity + Confidentiality
# ==========================================================

HASH_ALGORITHM = "SHA-256"

GENESIS_HASH = "GENESIS"

ENCRYPTION_ALGORITHM = (
    "AES-256-GCM"
)


AES_KEY_B64 = os.getenv(
    "S3_AES_KEY_B64"
)


if not AES_KEY_B64:

    print(
        "ERROR: S3_AES_KEY_B64 "
        "is not set."
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
        "ERROR: AES-256 requires "
        "exactly 32 decoded key bytes."
    )

    sys.exit(1)


aesgcm = AESGCM(
    AES_KEY
)


# ==========================================================
# Local MySQL Configuration
# ==========================================================

MYSQL_HOST = os.getenv(
    "S3_MYSQL_HOST",
    "127.0.0.1"
)


MYSQL_PORT_TEXT = os.getenv(
    "S3_MYSQL_PORT",
    "3306"
)


MYSQL_DATABASE = os.getenv(
    "S3_MYSQL_DB",
    "dbtest"
)


MYSQL_TABLE = os.getenv(
    "S3_MYSQL_TABLE",
    "table_stock"
)


MYSQL_USER = os.getenv(
    "S3_MYSQL_USER",
    "usertest"
)


MYSQL_PASSWORD = os.getenv(
    "LOCAL_DB_PASSWORD"
)


MYSQL_DRIVER = (
    "com.mysql.cj.jdbc.Driver"
)


try:

    MYSQL_PORT = int(
        MYSQL_PORT_TEXT
    )


except ValueError:

    print(
        "ERROR: S3_MYSQL_PORT "
        "must be an integer."
    )

    sys.exit(1)


if not MYSQL_PASSWORD:

    print(
        "ERROR: LOCAL_DB_PASSWORD "
        "is not set."
    )

    sys.exit(1)


MYSQL_URL = (

    f"jdbc:mysql://"
    f"{MYSQL_HOST}:"
    f"{MYSQL_PORT}/"
    f"{MYSQL_DATABASE}"

    "?useSSL=false"
    "&serverTimezone=UTC"
)


# ==========================================================
# Indicator 12 - Security Event Logging
# ==========================================================

AUDIT_LOG = os.getenv(

    "S3_AUDIT_LOG",

    "/var/log/"
    "cips_sruda_s3_audit.log"
)


RUN_ID = os.getenv(

    "S3_RUN_ID",

    (
        f"S3-{SOURCE_TABLE}-"
        f"{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    )
)


audit_time_total = 0.0


def audit_event(
    event,
    status,
    decision="N/A",
    reason="N/A",
    details="N/A"
):

    global audit_time_total


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

            f"Unable to write "
            f"S3 audit log: {exc}"

        ) from exc


    finally:

        audit_time_total += (

            time.perf_counter()

            - start
        )


# ==========================================================
# Resource Monitor
# ==========================================================

class ResourceMonitor:

    def __init__(
        self
    ):

        self.cpu_samples = []

        self.memory_samples = []

        self.stop_event = (
            threading.Event()
        )

        self.thread = None


    @staticmethod
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


    @staticmethod
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
            meminfo["MemTotal"]
        )


        available = (
            meminfo["MemAvailable"]
        )


        return (
            (
                total
                - available
            )
            / total
        ) * 100


    def _monitor(
        self
    ):

        (
            previous_total,
            previous_idle
        ) = self.get_cpu_values()


        while not self.stop_event.wait(
            0.5
        ):

            (
                current_total,
                current_idle
            ) = self.get_cpu_values()


            total_delta = (
                current_total
                - previous_total
            )


            idle_delta = (
                current_idle
                - previous_idle
            )


            if total_delta > 0:

                self.cpu_samples.append(

                    (
                        (
                            total_delta
                            - idle_delta
                        )
                        / total_delta
                    )
                    * 100
                )


            self.memory_samples.append(
                self.get_memory_percent()
            )


            previous_total = (
                current_total
            )

            previous_idle = (
                current_idle
            )


    def start(
        self
    ):

        self.thread = (
            threading.Thread(
                target=self._monitor,
                daemon=True
            )
        )

        self.thread.start()


    def stop(
        self
    ):

        self.stop_event.set()


        if self.thread:

            self.thread.join()


    def results(
        self
    ):

        return {

            "avg_cpu": (

                sum(
                    self.cpu_samples
                )

                / len(
                    self.cpu_samples
                )

                if self.cpu_samples

                else 0.0
            ),


            "peak_cpu": (

                max(
                    self.cpu_samples
                )

                if self.cpu_samples

                else 0.0
            ),


            "avg_memory": (

                sum(
                    self.memory_samples
                )

                / len(
                    self.memory_samples
                )

                if self.memory_samples

                else 0.0
            ),


            "peak_memory": (

                max(
                    self.memory_samples
                )

                if self.memory_samples

                else 0.0
            )
        }


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

            f"Unable to access "
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
# Indicator 11 - Local Database Connectivity Check
# ==========================================================

def check_local_mysql_connectivity():

    environment = (
        os.environ.copy()
    )


    # Avoid putting the password directly
    # in the command-line arguments.

    environment[
        "MYSQL_PWD"
    ] = MYSQL_PASSWORD


    result = subprocess.run(

        [
            "mysql",

            "--protocol=TCP",

            "-h",
            MYSQL_HOST,

            "-P",
            str(
                MYSQL_PORT
            ),

            "-u",
            MYSQL_USER,

            "-D",
            MYSQL_DATABASE,

            "-N",
            "-B",

            "-e",
            "SELECT 1;"
        ],

        env=environment,

        capture_output=True,

        text=True
    )


    if result.returncode != 0:

        errors = (
            result.stderr
            .strip()
            .splitlines()
        )


        reason = (

            errors[0]

            if errors

            else (
                "Local MySQL "
                "connection failed"
            )
        )


        return (
            False,
            reason
        )


    if (
        result.stdout.strip()
        != "1"
    ):

        return (

            False,

            "Local MySQL connectivity "
            "query returned an "
            "unexpected result"
        )


    return (

        True,

        "Local MySQL connection available"
    )


# ==========================================================
# SHA-256
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
# AES-256-GCM Decryption
# ==========================================================

def decrypt_encrypted_row(
    encrypted_line
):

    try:

        encrypted_bytes = (
            base64.b64decode(
                encrypted_line,
                validate=True
            )
        )


    except Exception as exc:

        raise RuntimeError(
            "Invalid Base64 encrypted row."
        ) from exc


    if len(
        encrypted_bytes
    ) <= 28:

        raise RuntimeError(

            "Encrypted row is too short "
            "for valid AES-GCM data."
        )


    nonce = (
        encrypted_bytes[:12]
    )


    ciphertext = (
        encrypted_bytes[12:]
    )


    try:

        plaintext = aesgcm.decrypt(

            nonce,

            ciphertext,

            None
        )


    except InvalidTag as exc:

        raise RuntimeError(

            "AES-GCM authentication failed: "
            "wrong key or encrypted data modified."

        ) from exc


    try:

        return plaintext.decode(
            "utf-8"
        )


    except UnicodeDecodeError as exc:

        raise RuntimeError(

            "Decrypted row is "
            "not valid UTF-8."

        ) from exc


# ==========================================================
# Decrypt + Integrity Verification
# ==========================================================

def decrypt_and_verify_dataset():

    encrypted_part_files = (
        get_hdfs_part_files(
            HDFS_PATH
        )
    )


    hdfs_remove(
        HDFS_DECRYPTED_PATH
    )


    hdfs_mkdir(
        HDFS_DECRYPTED_PATH
    )


    expected_previous_hash = (
        GENESIS_HASH
    )


    encrypted_records = 0

    decrypted_records = 0

    verified_records = 0

    violation_records = 0

    first_violations = []


    for input_part in (
        encrypted_part_files
    ):

        part_name = (
            os.path.basename(
                input_part
            )
        )


        output_part = (

            f"{HDFS_DECRYPTED_PATH}/"

            f"{part_name}"
        )


        print(
            f"Decrypting + verifying: "
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

                encrypted_line = (
                    raw_line.rstrip(
                        "\r\n"
                    )
                )


                if not encrypted_line:

                    continue


                encrypted_records += 1


                protected_row = (
                    decrypt_encrypted_row(
                        encrypted_line
                    )
                )


                decrypted_records += 1


                try:

                    (
                        row_data,
                        stored_previous_hash,
                        stored_current_hash
                    ) = (
                        protected_row.rsplit(
                            ",",
                            2
                        )
                    )


                except ValueError:

                    violation_records += 1


                    if len(
                        first_violations
                    ) < 10:

                        first_violations.append(

                            "Malformed protected "
                            f"row at record "
                            f"{encrypted_records}"
                        )


                    expected_previous_hash = (
                        "__INVALID_CHAIN__"
                    )


                    continue


                verified_records += 1


                link_valid = (

                    stored_previous_hash

                    == expected_previous_hash
                )


                calculated_current_hash = (
                    calculate_current_hash(

                        stored_previous_hash,

                        row_data
                    )
                )


                hash_valid = (

                    calculated_current_hash

                    == stored_current_hash
                )


                if (
                    not link_valid
                    or not hash_valid
                ):

                    violation_records += 1


                    if len(
                        first_violations
                    ) < 10:

                        reasons = []


                        if not link_valid:

                            reasons.append(
                                "previous-hash mismatch"
                            )


                        if not hash_valid:

                            reasons.append(
                                "current-hash mismatch"
                            )


                        first_violations.append(

                            f"Record "
                            f"{encrypted_records}: "
                            f"{', '.join(reasons)}"
                        )


                expected_previous_hash = (
                    stored_current_hash
                )


                writer.stdin.write(

                    protected_row

                    + "\n"
                )


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

                "Unable to read encrypted "
                "S3 HDFS data:\n"

                + reader_error
            )


        if writer_returncode != 0:

            raise RuntimeError(

                "Unable to write temporary "
                "decrypted S3 data:\n"

                + writer_error
            )


    record_count_valid = (

        encrypted_records
        == EXPECTED_RECORDS

        and decrypted_records
        == EXPECTED_RECORDS

        and verified_records
        == EXPECTED_RECORDS
    )


    if not record_count_valid:

        violation_records += 1


        first_violations.append(

            "Record-count mismatch: "

            f"expected "
            f"{EXPECTED_RECORDS}, "

            f"encrypted "
            f"{encrypted_records}, "

            f"decrypted "
            f"{decrypted_records}, "

            f"verified "
            f"{verified_records}"
        )


    integrity_pass = (

        violation_records == 0

        and record_count_valid
    )


    return {

        "pass":
            integrity_pass,

        "decryption_status":
            "SUCCESS",

        "encrypted_records":
            encrypted_records,

        "decrypted_records":
            decrypted_records,

        "verified_records":
            verified_records,

        "violations":
            violation_records,

        "final_chain_hash":
            expected_previous_hash,

        "details":
            first_violations
    }


# ==========================================================
# Header
# ==========================================================

print(
    "=" * 72
)

print(
    "S3 - HDFS + DATABASE CHECKS "
    "+ SECURITY LOGGING + PYSPARK"
)

print(
    "=" * 72
)


print(
    f"Strategy             : "
    f"{STRATEGY}"
)

print(
    f"Dataset scale        : "
    f"{DATASET_SCALE}"
)

print(
    f"Source table         : "
    f"{SOURCE_TABLE}"
)

print(
    f"Expected records     : "
    f"{EXPECTED_RECORDS}"
)

print(
    f"Encrypted HDFS input : "
    f"{HDFS_PATH}/part*"
)

print(
    f"Local MySQL          : "
    f"{MYSQL_HOST}:"
    f"{MYSQL_PORT}/"
    f"{MYSQL_DATABASE}"
)

print(
    f"Audit log            : "
    f"{AUDIT_LOG}"
)

print(
    f"Run ID               : "
    f"{RUN_ID}"
)

print()


# Preparation outside timing.

hdfs_remove(
    HDFS_DECRYPTED_PATH
)


security_monitor = (
    ResourceMonitor()
)

security_monitor.start()


hdfs_check_time = 0.0

mysql_connectivity_time = 0.0

decrypt_verify_time = 0.0

verification = None


try:

    audit_event(

        "SCRIPT2_START",

        "STARTED",

        "N/A",

        "N/A",

        f"source_table={SOURCE_TABLE}"
    )


    # ======================================================
    # Indicator 10
    # ======================================================

    print(
        "=" * 72
    )

    print(
        "STAGE 1 - HDFS DATA "
        "AVAILABILITY CHECK"
    )

    print(
        "=" * 72
    )


    start = (
        time.perf_counter()
    )


    (
        hdfs_available,
        hdfs_reason,
        hdfs_part_count
    ) = (
        check_hdfs_availability(
            HDFS_PATH
        )
    )


    hdfs_check_time = (

        time.perf_counter()

        - start
    )


    if not hdfs_available:

        audit_event(

            "HDFS_AVAILABILITY",

            "FAIL",

            "BLOCK",

            "HDFS_DATASET_UNAVAILABLE",

            hdfs_reason
        )


        print(
            "HDFS availability : FAIL"
        )

        print(
            f"Reason            : "
            f"{hdfs_reason}"
        )

        print(
            "Pipeline decision : BLOCK"
        )


        raise RuntimeError(

            "HDFS availability "
            "check failed."
        )


    audit_event(

        "HDFS_AVAILABILITY",

        "PASS",

        "ALLOW",

        "N/A",

        (
            f"part_files="
            f"{hdfs_part_count}"
        )
    )


    print(
        "HDFS availability : PASS"
    )

    print(
        f"Part files        : "
        f"{hdfs_part_count}"
    )

    print(
        "Pipeline decision : CONTINUE"
    )


    # ======================================================
    # Indicator 11
    # ======================================================

    print()

    print(
        "=" * 72
    )

    print(
        "STAGE 2 - LOCAL DATABASE "
        "CONNECTIVITY CHECK"
    )

    print(
        "=" * 72
    )


    start = (
        time.perf_counter()
    )


    (
        mysql_available,
        mysql_reason
    ) = (
        check_local_mysql_connectivity()
    )


    mysql_connectivity_time = (

        time.perf_counter()

        - start
    )


    if not mysql_available:

        audit_event(

            "MYSQL_CONNECTIVITY",

            "FAIL",

            "BLOCK",

            "LOCAL_DATABASE_UNAVAILABLE",

            mysql_reason
            .replace(
                "\t",
                " "
            )
            .replace(
                "\n",
                " "
            )
        )


        print(
            "Database connectivity : FAIL"
        )

        print(
            f"Reason                : "
            f"{mysql_reason}"
        )

        print(
            "Output processing     : BLOCKED"
        )


        raise RuntimeError(

            "Local MySQL connectivity "
            "check failed."
        )


    audit_event(

        "MYSQL_CONNECTIVITY",

        "PASS",

        "ALLOW",

        "N/A",

        "Local MySQL connection available"
    )


    print(
        "Database connectivity : PASS"
    )

    print(
        "Output processing     : ALLOWED"
    )


    # ======================================================
    # S2 protections retained in S3
    # ======================================================

    print()

    print(
        "=" * 72
    )

    print(
        "STAGE 3 - AES DECRYPTION "
        "+ HASH-CHAIN VERIFICATION"
    )

    print(
        "=" * 72
    )


    start = (
        time.perf_counter()
    )


    verification = (
        decrypt_and_verify_dataset()
    )


    decrypt_verify_time = (

        time.perf_counter()

        - start
    )


    if not verification[
        "pass"
    ]:

        audit_event(

            "DECRYPTION_INTEGRITY",

            "FAIL",

            "BLOCK",

            "INTEGRITY_VERIFICATION_FAILED",

            (
                f"violations="
                f"{verification['violations']}"
            )
        )


        print(
            "Decryption status      : SUCCESS"
        )

        print(
            "Integrity verification : FAIL"
        )

        print(
            "Pipeline decision      : BLOCK"
        )


        raise RuntimeError(

            "Integrity verification failed."
        )


    audit_event(

        "DECRYPTION_INTEGRITY",

        "PASS",

        "ALLOW",

        "N/A",

        (
            f"verified_records="
            f"{verification['verified_records']}"
        )
    )


    print(
        "Decryption status      : SUCCESS"
    )

    print(
        "Integrity verification : PASS"
    )

    print(
        "Security decision      : ALLOW"
    )


except Exception as exc:

    security_monitor.stop()


    security_resources = (
        security_monitor.results()
    )


    hdfs_remove(
        HDFS_DECRYPTED_PATH
    )


    try:

        audit_event(

            "PIPELINE_END",

            "FAIL",

            "BLOCK",

            "SECURITY_OR_PROCESSING_FAILURE",

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


    print()

    print(
        "=" * 72
    )

    print(
        "S3 PIPELINE BLOCKED"
    )

    print(
        "=" * 72
    )


    print(
        f"Reason                : "
        f"{exc}"
    )

    print(
        "PySpark               : "
        "NOT EXECUTED"
    )

    print(
        "Local MySQL write     : "
        "NOT EXECUTED"
    )

    print(
        f"Audit log             : "
        f"{AUDIT_LOG}"
    )

    print(
        "=" * 72
    )


    sys.exit(2)


security_monitor.stop()


security_resources = (
    security_monitor.results()
)


# ==========================================================
# Start Spark
# Spark startup outside measured PySpark time
# ==========================================================

spark = (

    SparkSession.builder

    .appName(
        "CIPS-SRUDA-S3-Protected-Analytics"
    )

    .getOrCreate()
)


spark.sparkContext.setLogLevel(
    "WARN"
)


# ==========================================================
# Protected Schema
# ==========================================================

protected_schema = StructType([

    StructField(
        "id",
        IntegerType(),
        True
    ),

    StructField(
        "product_id",
        IntegerType(),
        True
    ),

    StructField(
        "purchasing_price",
        DoubleType(),
        True
    ),

    StructField(
        "quantity",
        DoubleType(),
        True
    ),

    StructField(
        "stock_date",
        TimestampType(),
        True
    ),

    StructField(
        "previous_hash",
        StringType(),
        True
    ),

    StructField(
        "current_hash",
        StringType(),
        True
    )
])


pipeline_monitor = (
    ResourceMonitor()
)

pipeline_monitor.start()


# ==========================================================
# Stage 4 - PySpark
# ==========================================================

print()

print(
    "=" * 72
)

print(
    "STAGE 4 - PYSPARK PROCESSING"
)

print(
    "=" * 72
)


pyspark_start = (
    time.perf_counter()
)


try:

    protected_df = (

        spark.read

        .option(
            "header",
            "false"
        )

        .option(
            "timestampFormat",
            "yyyy-MM-dd HH:mm:ss.S"
        )

        .option(
            "mode",
            "FAILFAST"
        )

        .schema(
            protected_schema
        )

        .csv(
            HDFS_DECRYPTED_INPUT
        )
    )


    output_df = (
        protected_df.select(

            "id",

            "product_id",

            "purchasing_price",

            "quantity",

            "stock_date"
        )
    )


    output_df = (
        output_df.persist(
            StorageLevel.MEMORY_AND_DISK
        )
    )


    output_records = (
        output_df.count()
    )


except Exception as exc:

    pyspark_end = (
        time.perf_counter()
    )


    pipeline_monitor.stop()

    spark.stop()


    hdfs_remove(
        HDFS_DECRYPTED_PATH
    )


    try:

        audit_event(

            "PYSPARK_PROCESSING",

            "FAIL",

            "BLOCK",

            "PYSPARK_FAILURE",

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


        audit_event(

            "PIPELINE_END",

            "FAIL",

            "BLOCK",

            "PROCESSING_FAILURE",

            "PySpark processing failed"
        )


    except Exception as log_exc:

        print(
            f"AUDIT ERROR: "
            f"{log_exc}"
        )


    print(
        f"ERROR: PySpark processing failed: "
        f"{exc}"
    )


    sys.exit(1)


pyspark_end = (
    time.perf_counter()
)


pyspark_processing_time = (

    pyspark_end

    - pyspark_start
)


audit_event(

    "PYSPARK_PROCESSING",

    "SUCCESS",

    "ALLOW",

    "N/A",

    (
        f"output_records="
        f"{output_records}"
    )
)


# ==========================================================
# Output Count Validation
# ==========================================================

if (
    output_records
    != EXPECTED_RECORDS
):

    pipeline_monitor.stop()

    output_df.unpersist()

    spark.stop()


    hdfs_remove(
        HDFS_DECRYPTED_PATH
    )


    audit_event(

        "OUTPUT_VALIDATION",

        "FAIL",

        "BLOCK",

        "RECORD_COUNT_MISMATCH",

        (
            f"expected="
            f"{EXPECTED_RECORDS};"

            f"actual="
            f"{output_records}"
        )
    )


    audit_event(

        "PIPELINE_END",

        "FAIL",

        "BLOCK",

        "OUTPUT_VALIDATION_FAILURE",

        "Local MySQL write blocked"
    )


    print(
        "ERROR: PySpark output "
        "record-count mismatch."
    )

    print(
        f"Expected : "
        f"{EXPECTED_RECORDS}"
    )

    print(
        f"Actual   : "
        f"{output_records}"
    )

    print(
        "Local MySQL write BLOCKED."
    )


    sys.exit(2)


# ==========================================================
# Stage 5 - Local MySQL Write
# ==========================================================

print()

print(
    "=" * 72
)

print(
    "STAGE 5 - LOCAL MYSQL WRITE"
)

print(
    "=" * 72
)


mysql_start = (
    time.perf_counter()
)


mysql_status = (
    "FAILED"
)

mysql_error = (
    "N/A"
)


try:

    (

        output_df.write

        .format(
            "jdbc"
        )

        .option(
            "url",
            MYSQL_URL
        )

        .option(
            "dbtable",
            MYSQL_TABLE
        )

        .option(
            "user",
            MYSQL_USER
        )

        .option(
            "password",
            MYSQL_PASSWORD
        )

        .option(
            "driver",
            MYSQL_DRIVER
        )

        .mode(
            "append"
        )

        .save()
    )


    mysql_status = (
        "SUCCESS"
    )


except Exception as exc:

    mysql_error = (
        str(exc)
    )


mysql_end = (
    time.perf_counter()
)


mysql_write_time = (

    mysql_end

    - mysql_start
)


if (
    mysql_status
    == "SUCCESS"
):

    audit_event(

        "MYSQL_WRITE",

        "SUCCESS",

        "ALLOW",

        "N/A",

        (
            f"records="
            f"{output_records}"
        )
    )


    audit_event(

        "PIPELINE_END",

        "SUCCESS",

        "ALLOW",

        "N/A",

        (
            f"output_records="
            f"{output_records}"
        )
    )


else:

    audit_event(

        "MYSQL_WRITE",

        "FAIL",

        "BLOCK",

        "MYSQL_WRITE_FAILURE",

        mysql_error
        .replace(
            "\t",
            " "
        )
        .replace(
            "\n",
            " "
        )[:500]
    )


    audit_event(

        "PIPELINE_END",

        "FAIL",

        "BLOCK",

        "MYSQL_WRITE_FAILURE",

        (
            "Pipeline could not complete "
            "Local MySQL write"
        )
    )


pipeline_monitor.stop()


pipeline_resources = (
    pipeline_monitor.results()
)


output_df.unpersist()

spark.stop()


hdfs_remove(
    HDFS_DECRYPTED_PATH
)


# ==========================================================
# Performance Results
# ==========================================================

hdfs_size_bytes = (
    get_hdfs_size_bytes(
        HDFS_PATH
    )
)


hdfs_size_mb = (

    hdfs_size_bytes

    / (1024 ** 2)
)


s2_script2_processing_time = decrypt_verify_time

s3_script2_control_time = (
    hdfs_check_time
    + mysql_connectivity_time
    + audit_time_total
)

# S3 Script 2 = S2 Script 2 processing + S3 controls.
# Count decryption and verification only once.
additional_security_processing_time = (
    s2_script2_processing_time
    + s3_script2_control_time
)


script2_total_measured_time = (

    additional_security_processing_time

    + pyspark_processing_time

    + mysql_write_time
)


pipeline_duration = (

    pyspark_processing_time

    + mysql_write_time
)


security_duration = (
    additional_security_processing_time
)


measured_duration = (

    security_duration

    + pipeline_duration
)


if measured_duration > 0:

    weighted_average_cpu = (

        (
            security_resources[
                "avg_cpu"
            ]
            * security_duration
        )

        +

        (
            pipeline_resources[
                "avg_cpu"
            ]
            * pipeline_duration
        )

    ) / measured_duration


    weighted_average_memory = (

        (
            security_resources[
                "avg_memory"
            ]
            * security_duration
        )

        +

        (
            pipeline_resources[
                "avg_memory"
            ]
            * pipeline_duration
        )

    ) / measured_duration


else:

    weighted_average_cpu = 0.0

    weighted_average_memory = 0.0


overall_peak_cpu = max(

    security_resources[
        "peak_cpu"
    ],

    pipeline_resources[
        "peak_cpu"
    ]
)


overall_peak_memory = max(

    security_resources[
        "peak_memory"
    ],

    pipeline_resources[
        "peak_memory"
    ]
)


execution_status = (

    "SUCCESS"

    if (

        verification
        is not None

        and verification[
            "pass"
        ]

        and output_records
        == EXPECTED_RECORDS

        and mysql_status
        == "SUCCESS"
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
# Final Result
# ==========================================================

print()

print(
    "=" * 72
)

print(
    "S3 - FINAL RESULT"
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
    f"Encrypted records                     : "
    f"{verification['encrypted_records']}"
)

print(
    f"Decrypted records                     : "
    f"{verification['decrypted_records']}"
)

print(
    f"Verified protected records            : "
    f"{verification['verified_records']}"
)

print(
    f"Output records                        : "
    f"{output_records}"
)


print(
    "HDFS availability                     : "
    "PASS"
)

print(
    "Local DB connectivity                 : "
    "PASS"
)

print(
    f"Decryption status                     : "
    f"{verification['decryption_status']}"
)

print(
    f"Integrity violations                  : "
    f"{verification['violations']}"
)

print(
    "Integrity verification                : "
    "PASS"
)

print(
    f"Local MySQL write status              : "
    f"{mysql_status}"
)

print(
    f"Execution status                      : "
    f"{execution_status}"
)


print()


print(
    f"HDFS availability-check time          : "
    f"{hdfs_check_time:.4f} seconds"
)

print(
    f"Local DB connectivity-check time      : "
    f"{mysql_connectivity_time:.4f} seconds"
)

print(
    f"S2 Script 2 processing time           : "
    f"(decryption + verification)           : "
    f"{decrypt_verify_time:.2f} seconds"
)

print(
    f"S3 audit logging time                 : "
    f"{audit_time_total:.4f} seconds"
)

print(
    f"S3 Script 2 control time              : "
    f"(availability + connectivity + audit) : "
    f"{s3_script2_control_time:.4f} seconds"
)

print(
    f"S3 Script 2 cumulative security time  : "
    f"{additional_security_processing_time:.2f} seconds"
)

print(
    f"PySpark processing time               : "
    f"{pyspark_processing_time:.2f} seconds"
)

print(
    f"Local MySQL write time                : "
    f"{mysql_write_time:.2f} seconds"
)

print(
    f"S3 Script 2 total measured time       : "
    f"{script2_total_measured_time:.2f} seconds"
)


print()


print(
    f"Average CPU utilization               : "
    f"{weighted_average_cpu:.2f}%"
)

print(
    f"Peak CPU utilization                  : "
    f"{overall_peak_cpu:.2f}%"
)

print(
    f"Average memory utilization            : "
    f"{weighted_average_memory:.2f}%"
)

print(
    f"Peak memory utilization               : "
    f"{overall_peak_memory:.2f}%"
)

print(
    f"HDFS encrypted storage size           : "
    f"{hdfs_size_mb:.4f} MB"
)


print()


print(
    f"Encryption algorithm                  : "
    f"{ENCRYPTION_ALGORITHM}"
)

print(
    f"AES key size                          : "
    f"{len(AES_KEY) * 8} bits"
)

print(
    f"Hash algorithm                        : "
    f"{HASH_ALGORITHM}"
)

print(
    f"Final verified chain hash             : "
    f"{verification['final_chain_hash']}"
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
