import base64
import hashlib
import os
import subprocess
import sys
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from pyspark.sql import SparkSession
from pyspark.sql.types import (
    StructType,
    StructField,
    IntegerType,
    DoubleType,
    TimestampType,
    StringType
)
from pyspark.storagelevel import StorageLevel


# ==========================================================
# S2 - Confidentiality + Integrity Verification
#      + PySpark Processing
# ==========================================================
#
# Final encrypted HDFS input:
#
# /security_lab/s2/part*
#
# Each HDFS line contains:
#
# Base64(
#     12-byte AES-GCM nonce
#     +
#     ciphertext
#     +
#     authentication tag
# )
#
# After successful decryption:
#
# id,product_id,purchasing_price,quantity,stock_date,
# previous_hash,current_hash
#
# Pipeline:
#
# /security_lab/s2/part*
#       ↓
# AES-256-GCM decryption
#       ↓
# SHA-256 hash-chain verification
#       ↓
# PASS
#       ↓
# temporary decrypted protected dataset
#       ↓
# PySpark processing
#       ↓
# remove hash metadata
#       ↓
# Local MySQL table_stock
#
# Any decryption/integrity failure:
#
# FAIL → BLOCK
#
# IMPORTANT:
# - /security_lab/s0 is NOT modified.
# - /security_lab/s1 is NOT modified.
# - Final /security_lab/s2 remains encrypted.
# - Temporary decrypted S2 data is removed after execution.
# ==========================================================


STRATEGY = "S2"


# ==========================================================
# Dataset Configuration
# ==========================================================

TABLE = os.getenv("SOURCE_TABLE")


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


if not TABLE:

    print("ERROR: SOURCE_TABLE is not set.")
    print()
    print("Choose one:")
    print('export SOURCE_TABLE="table_stock100"')
    print('export SOURCE_TABLE="table_stock20K"')
    print('export SOURCE_TABLE="table_stock4M"')

    sys.exit(1)


if TABLE not in DATASETS:

    print(
        f"ERROR: Invalid SOURCE_TABLE: {TABLE}"
    )

    sys.exit(1)


DATASET_SCALE = (
    DATASETS[TABLE]["scale"]
)

EXPECTED_RECORDS = (
    DATASETS[TABLE]["expected_records"]
)


# ==========================================================
# HDFS Configuration
# ==========================================================

# Final encrypted S2 dataset
HDFS_PATH = "/security_lab/s2"

HDFS_INPUT_PATH = (
    "hdfs:///security_lab/s2/part*"
)

# Temporary decrypted protected dataset.
#
# This is used only after successful decryption
# and integrity verification.
HDFS_DECRYPTED_PATH = (
    "/security_lab/s2_decrypted"
)

HDFS_DECRYPTED_INPUT = (
    "hdfs:///security_lab/s2_decrypted/part*"
)


# ==========================================================
# Integrity Configuration
# ==========================================================

HASH_ALGORITHM = "SHA-256"

GENESIS_HASH = "GENESIS"


# ==========================================================
# Confidentiality Configuration
# ==========================================================

ENCRYPTION_ALGORITHM = "AES-256-GCM"

AES_KEY_B64 = os.getenv(
    "S2_AES_KEY_B64"
)


if not AES_KEY_B64:

    print(
        "ERROR: S2_AES_KEY_B64 is not set."
    )

    print()
    print("Run:")

    print(
        'export S2_AES_KEY_B64="'
        '<your-base64-encoded-32-byte-key>"'
    )

    sys.exit(1)


try:

    AES_KEY = base64.b64decode(
        AES_KEY_B64,
        validate=True
    )

except Exception:

    print(
        "ERROR: S2_AES_KEY_B64 "
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


aesgcm = AESGCM(
    AES_KEY
)


# ==========================================================
# Local MySQL Configuration
# ==========================================================

MYSQL_URL = (
    "jdbc:mysql://127.0.0.1:3306/dbtest"
    "?useSSL=false&serverTimezone=UTC"
)

MYSQL_TABLE = "table_stock"

# Same Local MySQL account as S0/S1
# for experimental comparability.
MYSQL_USER = "usertest"

MYSQL_PASSWORD = os.getenv(
    "LOCAL_DB_PASSWORD"
)

# Current Connector/J driver
MYSQL_DRIVER = (
    "com.mysql.cj.jdbc.Driver"
)


if not MYSQL_PASSWORD:

    print(
        "ERROR: LOCAL_DB_PASSWORD is not set."
    )

    print("Run:")

    print(
        "export LOCAL_DB_PASSWORD="
        "'your_password'"
    )

    sys.exit(1)


# ==========================================================
# Resource Monitor
# ==========================================================

class ResourceMonitor:

    def __init__(self):

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


        total = (
            idle_total
            + active_total
        )


        return (
            total,
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
                    value
                    .strip()
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


    def _monitor(self):

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

                cpu_percent = (
                    (
                        total_delta
                        - idle_delta
                    )
                    / total_delta
                ) * 100


                self.cpu_samples.append(
                    cpu_percent
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


    def start(self):

        self.thread = (
            threading.Thread(
                target=self._monitor,
                daemon=True
            )
        )

        self.thread.start()


    def stop(self):

        self.stop_event.set()

        if self.thread:

            self.thread.join()


    def results(self):

        average_cpu = (
            sum(self.cpu_samples)
            / len(self.cpu_samples)
            if self.cpu_samples
            else 0.0
        )


        peak_cpu = (
            max(self.cpu_samples)
            if self.cpu_samples
            else 0.0
        )


        average_memory = (
            sum(self.memory_samples)
            / len(self.memory_samples)
            if self.memory_samples
            else 0.0
        )


        peak_memory = (
            max(self.memory_samples)
            if self.memory_samples
            else 0.0
        )


        return {

            "avg_cpu": average_cpu,

            "peak_cpu": peak_cpu,

            "avg_memory": average_memory,

            "peak_memory": peak_memory
        }


# ==========================================================
# HDFS Utility Functions
# ==========================================================

def hdfs_remove(path):

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


def hdfs_mkdir(path):

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


    # Must use the exact same
    # deterministic ordering as
    # S1 and S2 Script 1.
    files.sort()


    if not files:

        raise RuntimeError(
            f"No HDFS part files "
            f"found in {path}."
        )


    return files


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


# ==========================================================
# SHA-256 Hash Function
#
# MUST remain identical to S1
# and S2 Script 1.
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
# AES-256-GCM Decryption
# ==========================================================

def decrypt_encrypted_row(
    encrypted_line
):
    """
    Input:

        Base64(
            nonce
            +
            ciphertext
            +
            GCM authentication tag
        )

    Output:

        id,product_id,purchasing_price,
        quantity,stock_date,
        previous_hash,current_hash
    """

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


    # 12-byte nonce +
    # at least 16-byte GCM tag.
    if len(encrypted_bytes) <= 28:

        raise RuntimeError(
            "Encrypted row is too short "
            "to contain valid AES-GCM data."
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
            "AES-GCM authentication failed. "
            "Wrong key or encrypted data "
            "has been modified."
        ) from exc


    try:

        return plaintext.decode(
            "utf-8"
        )

    except UnicodeDecodeError as exc:

        raise RuntimeError(
            "Decrypted row is not valid UTF-8."
        ) from exc


# ==========================================================
# S2 Decryption + Integrity Verification
# ==========================================================

def decrypt_and_verify_dataset():
    """
    1. Read encrypted S2 HDFS rows.

    2. Decrypt each row using AES-256-GCM.

    3. Verify previous_hash/current_hash.

    4. Write successfully decrypted protected
       rows to temporary HDFS.

    5. Return integrity result.

    Any AES-GCM failure raises an exception
    and blocks the pipeline.
    """

    encrypted_part_files = (
        get_hdfs_part_files(
            HDFS_PATH
        )
    )


    # Remove any previous temporary
    # decrypted dataset.
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


    # ------------------------------------------------------
    # Process each encrypted HDFS part file
    # ------------------------------------------------------

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

            for raw_line in reader.stdout:

                encrypted_line = (
                    raw_line.rstrip(
                        "\r\n"
                    )
                )


                if not encrypted_line:
                    continue


                encrypted_records += 1


                # ==========================================
                # S2 Confidentiality Verification
                # ==========================================

                try:

                    protected_row = (
                        decrypt_encrypted_row(
                            encrypted_line
                        )
                    )

                except Exception as exc:

                    # Clean temporary plaintext before
                    # stopping the pipeline.
                    raise RuntimeError(
                        "S2 decryption/security "
                        "verification failed at "
                        f"record {encrypted_records}: "
                        f"{exc}"
                    ) from exc


                decrypted_records += 1


                # ==========================================
                # Separate original row + hash metadata
                # ==========================================

                try:

                    (
                        row_data,
                        stored_previous_hash,
                        stored_current_hash
                    ) = protected_row.rsplit(
                        ",",
                        2
                    )

                except ValueError:

                    violation_records += 1


                    if len(
                        first_violations
                    ) < 10:

                        first_violations.append(
                            (
                                "Malformed protected "
                                f"row at record "
                                f"{encrypted_records}"
                            )
                        )


                    expected_previous_hash = (
                        "__INVALID_CHAIN__"
                    )

                    continue


                verified_records += 1


                # ==========================================
                # Check Previous Hash Link
                # ==========================================

                link_valid = (
                    stored_previous_hash
                    == expected_previous_hash
                )


                # ==========================================
                # Recalculate Current SHA-256
                # ==========================================

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


                # ==========================================
                # Record Integrity Violation
                # ==========================================

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
                            (
                                f"Record "
                                f"{encrypted_records}: "
                                + ", ".join(
                                    reasons
                                )
                            )
                        )


                # ==========================================
                # Advance Expected Chain
                # ==========================================

                expected_previous_hash = (
                    stored_current_hash
                )


                # ==========================================
                # Temporary Decrypted Protected Dataset
                # ==========================================

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
                "S2 HDFS data:\n"
                + reader_error
            )


        if writer_returncode != 0:

            raise RuntimeError(
                "Unable to write temporary "
                "decrypted S2 data:\n"
                + writer_error
            )


    # ======================================================
    # Record Count Security Check
    # ======================================================

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
            (
                "Record-count mismatch: "
                f"expected {EXPECTED_RECORDS}, "
                f"encrypted {encrypted_records}, "
                f"decrypted {decrypted_records}, "
                f"verified {verified_records}"
            )
        )


    integrity_pass = (
        violation_records == 0
        and record_count_valid
    )


    return {

        "pass": integrity_pass,

        "decryption_status": "SUCCESS",

        "encrypted_records": (
            encrypted_records
        ),

        "decrypted_records": (
            decrypted_records
        ),

        "verified_records": (
            verified_records
        ),

        "violations": (
            violation_records
        ),

        "final_chain_hash": (
            expected_previous_hash
        ),

        "details": (
            first_violations
        )
    }


# ==========================================================
# Experiment Header
# ==========================================================

print("=" * 72)

print(
    "S2 - AES DECRYPTION + "
    "INTEGRITY VERIFICATION + "
    "PYSPARK PROCESSING"
)

print("=" * 72)


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
    f"{TABLE}"
)

print(
    f"Expected records     : "
    f"{EXPECTED_RECORDS}"
)

print(
    f"Encrypted HDFS input : "
    f"{HDFS_INPUT_PATH}"
)

print(
    f"Encryption algorithm : "
    f"{ENCRYPTION_ALGORITHM}"
)

print(
    f"AES key size         : "
    f"{len(AES_KEY) * 8} bits"
)

print(
    f"Hash algorithm       : "
    f"{HASH_ALGORITHM}"
)

print(
    f"Genesis hash         : "
    f"{GENESIS_HASH}"
)

print()


# ==========================================================
# Remove Previous Temporary Decrypted Data
#
# Preparation time is NOT measured.
# ==========================================================

hdfs_remove(
    HDFS_DECRYPTED_PATH
)


# ==========================================================
# Stage 1
# AES-256-GCM Decryption
# +
# SHA-256 Hash-Chain Verification
# ==========================================================

print("=" * 72)

print(
    "STAGE 1 - AES DECRYPTION "
    "+ HASH-CHAIN VERIFICATION"
)

print("=" * 72)


security_monitor = (
    ResourceMonitor()
)

security_monitor.start()


security_start = (
    time.perf_counter()
)


try:

    verification = (
        decrypt_and_verify_dataset()
    )


except Exception as exc:

    security_end = (
        time.perf_counter()
    )


    security_monitor.stop()


    # Delete any temporary decrypted
    # plaintext data.
    hdfs_remove(
        HDFS_DECRYPTED_PATH
    )


    print()

    print(
        "Decryption result     : FAIL"
    )

    print(
        "Integrity result      : "
        "NOT AUTHORIZED"
    )

    print()

    print(
        "Detected security problem:"
    )

    print(
        f"  - {exc}"
    )

    print()

    print("=" * 72)

    print(
        "SECURITY DECISION: BLOCK"
    )

    print(
        "PySpark processing was NOT executed."
    )

    print(
        "Local MySQL write was NOT executed."
    )

    print("=" * 72)

    sys.exit(2)


security_end = (
    time.perf_counter()
)


security_monitor.stop()


security_processing_time = (
    security_end
    - security_start
)


security_resources = (
    security_monitor.results()
)


# ==========================================================
# Security Results
# ==========================================================

print()

print(
    f"Encrypted records     : "
    f"{verification['encrypted_records']}"
)

print(
    f"Decrypted records     : "
    f"{verification['decrypted_records']}"
)

print(
    f"Verified records      : "
    f"{verification['verified_records']}"
)

print(
    f"Integrity violations  : "
    f"{verification['violations']}"
)

print(
    f"Decryption result     : "
    f"{verification['decryption_status']}"
)


if verification["pass"]:

    print(
        "Integrity result      : PASS"
    )


else:

    print(
        "Integrity result      : FAIL"
    )

    print()


    if verification["details"]:

        print(
            "Detected integrity problems:"
        )


        for detail in (
            verification["details"]
        ):

            print(
                f"  - {detail}"
            )


    # Remove temporary plaintext.
    hdfs_remove(
        HDFS_DECRYPTED_PATH
    )


    print()

    print("=" * 72)

    print(
        "SECURITY DECISION: BLOCK"
    )

    print(
        "PySpark processing was NOT executed."
    )

    print(
        "Local MySQL write was NOT executed."
    )

    print("=" * 72)


    sys.exit(2)


# ==========================================================
# Security Decision
#
# Only successfully decrypted AND
# integrity-verified data continues.
# ==========================================================

print()

print(
    "SECURITY DECISION: ALLOW"
)

print(
    "Decryption and integrity verification "
    "succeeded."
)


# ==========================================================
# Start Spark
#
# Spark startup is outside measured
# PySpark-processing time to remain
# comparable with S0 and S1.
# ==========================================================

spark = (

    SparkSession.builder

    .appName(
        "CIPS-SRUDA-S2-"
        "Confidentiality-Integrity"
    )

    .getOrCreate()
)


spark.sparkContext.setLogLevel(
    "WARN"
)


# ==========================================================
# Decrypted Protected HDFS Schema
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


# ==========================================================
# Stage 2 - PySpark Processing
# ==========================================================

print()

print("=" * 72)

print(
    "STAGE 2 - PYSPARK PROCESSING"
)

print("=" * 72)


pipeline_monitor = (
    ResourceMonitor()
)

pipeline_monitor.start()


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


    # Keep only original five analytical
    # columns, matching S0 and S1.

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


    # Force actual Spark execution.
    output_records = (
        output_df.count()
    )


except Exception as exc:

    pipeline_monitor.stop()

    spark.stop()

    hdfs_remove(
        HDFS_DECRYPTED_PATH
    )

    print()

    print(
        "ERROR: PySpark processing failed."
    )

    print(
        str(exc)
    )

    sys.exit(1)


pyspark_end = (
    time.perf_counter()
)


pyspark_processing_time = (
    pyspark_end
    - pyspark_start
)


# ==========================================================
# Record Count Validation Before MySQL
# ==========================================================

if output_records != EXPECTED_RECORDS:

    pipeline_monitor.stop()

    output_df.unpersist()

    spark.stop()

    hdfs_remove(
        HDFS_DECRYPTED_PATH
    )

    print()

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
# Stage 3 - Local MySQL Write
# ==========================================================

print()

print("=" * 72)

print(
    "STAGE 3 - LOCAL MYSQL WRITE"
)

print("=" * 72)


mysql_start = (
    time.perf_counter()
)


mysql_status = "FAILED"


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

    print()

    print(
        "ERROR: Local MySQL write failed."
    )

    print(
        str(exc)
    )


mysql_end = (
    time.perf_counter()
)


mysql_write_time = (
    mysql_end
    - mysql_start
)


# ==========================================================
# Stop Processing Resource Monitor
# ==========================================================

pipeline_monitor.stop()


pipeline_resources = (
    pipeline_monitor.results()
)


# ==========================================================
# Cleanup Spark Cache
# ==========================================================

output_df.unpersist()

spark.stop()


# ==========================================================
# Remove Temporary Decrypted HDFS Data
#
# Final /security_lab/s2 remains encrypted.
# ==========================================================

hdfs_remove(
    HDFS_DECRYPTED_PATH
)


# ==========================================================
# Final Encrypted HDFS Storage Size
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


# ==========================================================
# Script 2 Measured Time
#
# Does NOT include Spark startup.
# ==========================================================

script2_total_time = (
    security_processing_time
    + pyspark_processing_time
    + mysql_write_time
)


# ==========================================================
# Duration-Weighted CPU / Memory
#
# Security:
# AES decryption + hash verification
#
# Pipeline:
# PySpark + MySQL
# ==========================================================

pipeline_duration = (
    pyspark_processing_time
    + mysql_write_time
)


measured_duration = (
    security_processing_time
    + pipeline_duration
)


if measured_duration > 0:

    weighted_average_cpu = (

        (
            security_resources[
                "avg_cpu"
            ]
            * security_processing_time
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
            * security_processing_time
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


# ==========================================================
# Final Status
# ==========================================================

if (
    verification["pass"]
    and verification[
        "decryption_status"
    ] == "SUCCESS"
    and mysql_status == "SUCCESS"
    and output_records
        == EXPECTED_RECORDS
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

print("=" * 72)

print(
    "S2 - CONFIDENTIALITY + "
    "INTEGRITY + PYSPARK RESULT"
)

print("=" * 72)


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
    f"{TABLE}"
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
    f"Decryption status                     : "
    f"{verification['decryption_status']}"
)

print(
    f"Integrity violations                  : "
    f"{verification['violations']}"
)

print(
    f"Integrity verification                : "
    f"{'PASS' if verification['pass'] else 'FAIL'}"
)

print(
    f"Security decision                     : "
    f"{'ALLOW' if verification['pass'] else 'BLOCK'}"
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


# ----------------------------------------------------------
# Performance Measurements
# ----------------------------------------------------------

print(
    f"Decryption + hash verification time   : "
    f"{security_processing_time:.2f} seconds"
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
    f"Script 2 total measured time          : "
    f"{script2_total_time:.2f} seconds"
)


print()


# ----------------------------------------------------------
# Resource Measurements
# ----------------------------------------------------------

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


# ----------------------------------------------------------
# Security Detail
# ----------------------------------------------------------

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
    f"Genesis previous hash                 : "
    f"{GENESIS_HASH}"
)

print(
    f"Final verified chain hash             : "
    f"{verification['final_chain_hash']}"
)


print("=" * 72)


# ==========================================================
# I1 Guidance
# ==========================================================

print(
    "IMPORTANT FOR I1:"
)

print()

print(
    "Additional S2 security-processing time ="
)

print(
    "Hash-chain generation + encryption "
    "time from Script 1"
)

print(
    "+"
)

print(
    f"Decryption + hash verification time "
    f"({security_processing_time:.2f} seconds)"
)

print()


print(
    "Total S2 pipeline time ="
)

print(
    "Sqoop ingestion time"
)

print(
    "+ Hash-chain generation "
    "+ encryption time"
)

print(
    f"+ Decryption + hash verification time "
    f"({security_processing_time:.2f})"
)

print(
    f"+ PySpark processing time "
    f"({pyspark_processing_time:.2f})"
)

print(
    f"+ Local MySQL write time "
    f"({mysql_write_time:.2f})"
)

print("=" * 72)


sys.exit(
    final_returncode
)
