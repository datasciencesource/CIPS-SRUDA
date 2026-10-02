import hashlib
import os
import subprocess
import sys
import threading
import time

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
# S1 - Integrity Verification + PySpark Processing
# ==========================================================
#
# HDFS protected row:
#
# id,product_id,purchasing_price,quantity,stock_date,
# previous_hash,current_hash
#
# Pipeline:
#
# /security_lab/s1/part*
#       ↓
# Verify previous_hash + current_hash
#       ↓
# PASS → PySpark processing
#       ↓
# Remove hash columns from analytical output
#       ↓
# Local MySQL table_stock
#
# FAIL → BLOCK Local MySQL write
# ==========================================================

STRATEGY = "S1"

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
    print(f"ERROR: Invalid SOURCE_TABLE: {TABLE}")
    sys.exit(1)

DATASET_SCALE = DATASETS[TABLE]["scale"]
EXPECTED_RECORDS = DATASETS[TABLE]["expected_records"]


# ==========================================================
# HDFS Configuration
# ==========================================================

HDFS_PATH = "/security_lab/s1"
HDFS_INPUT_PATH = "hdfs:///security_lab/s1/part*"

HASH_ALGORITHM = "SHA-256"
GENESIS_HASH = "GENESIS"


# ==========================================================
# Local MySQL Configuration
# ==========================================================

MYSQL_URL = (
    "jdbc:mysql://127.0.0.1:3306/dbtest"
    "?useSSL=false&serverTimezone=UTC"
)

MYSQL_TABLE = "table_stock"

# Keep the same Local MySQL account used in S0
# so S0 vs S1 remains comparable.
MYSQL_USER = "usertest"

MYSQL_PASSWORD = os.getenv("LOCAL_DB_PASSWORD")

MYSQL_DRIVER = "com.mysql.jdbc.Driver"

if not MYSQL_PASSWORD:
    print("ERROR: LOCAL_DB_PASSWORD is not set.")
    print("Run:")
    print("export LOCAL_DB_PASSWORD='your_password'")
    sys.exit(1)


# ==========================================================
# Resource Monitoring
# ==========================================================

class ResourceMonitor:

    def __init__(self):
        self.cpu_samples = []
        self.memory_samples = []
        self.stop_event = threading.Event()
        self.thread = None

    @staticmethod
    def get_cpu_values():

        with open("/proc/stat", "r") as f:
            values = list(
                map(
                    float,
                    f.readline().split()[1:9]
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

        idle_total = idle + iowait

        active_total = (
            user
            + nice
            + system
            + irq
            + softirq
            + steal
        )

        total = idle_total + active_total

        return total, idle_total

    @staticmethod
    def get_memory_percent():

        meminfo = {}

        with open("/proc/meminfo", "r") as f:

            for line in f:

                key, value = line.split(
                    ":",
                    1
                )

                meminfo[key] = float(
                    value.strip().split()[0]
                )

        total = meminfo["MemTotal"]
        available = meminfo["MemAvailable"]

        return (
            (total - available)
            / total
        ) * 100

    def _monitor(self):

        previous_total, previous_idle = (
            self.get_cpu_values()
        )

        while not self.stop_event.wait(0.5):

            current_total, current_idle = (
                self.get_cpu_values()
            )

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

            previous_total = current_total
            previous_idle = current_idle

    def start(self):

        self.thread = threading.Thread(
            target=self._monitor,
            daemon=True
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
# HDFS Utilities
# ==========================================================

def get_hdfs_part_files():

    result = subprocess.run(
        [
            "hdfs",
            "dfs",
            "-ls",
            HDFS_PATH
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:

        raise RuntimeError(
            f"Unable to access {HDFS_PATH}"
        )

    files = []

    for line in result.stdout.splitlines():

        fields = line.split()

        if not fields:
            continue

        candidate = fields[-1]

        basename = os.path.basename(
            candidate
        )

        if basename.startswith("part"):
            files.append(candidate)

    # Must match Script 1 ordering.
    files.sort()

    if not files:
        raise RuntimeError(
            "No S1 HDFS part files found."
        )

    return files


def get_hdfs_size_bytes():

    result = subprocess.run(
        [
            "hdfs",
            "dfs",
            "-du",
            "-s",
            HDFS_PATH
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return 0

    try:
        return int(
            result.stdout.split()[0]
        )

    except (ValueError, IndexError):
        return 0


# ==========================================================
# SHA-256 Hash Function
#
# MUST be identical to Script 1.
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
        hash_input.encode("utf-8")
    ).hexdigest()


# ==========================================================
# S1 Hash-Chain Verification
# ==========================================================

def verify_hash_chain():

    part_files = get_hdfs_part_files()

    expected_previous_hash = GENESIS_HASH

    verified_records = 0
    violation_records = 0

    first_violations = []

    for input_part in part_files:

        print(
            f"Verifying: "
            f"{os.path.basename(input_part)}"
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

        line_number = 0

        for raw_line in reader.stdout:

            line_number += 1

            protected_row = (
                raw_line.rstrip("\r\n")
            )

            if not protected_row:
                continue

            verified_records += 1

            # ----------------------------------------------
            # Separate:
            #
            # original 5-field row
            # previous_hash
            # current_hash
            #
            # rsplit() is safer because it removes only
            # the final two hash columns.
            # ----------------------------------------------

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

                if len(first_violations) < 10:

                    first_violations.append(
                        (
                            f"Malformed protected row "
                            f"at record "
                            f"{verified_records}"
                        )
                    )

                # Force the following chain link to fail.
                expected_previous_hash = (
                    "__INVALID_CHAIN__"
                )

                continue

            # ----------------------------------------------
            # Check chain link
            # ----------------------------------------------

            link_valid = (
                stored_previous_hash
                == expected_previous_hash
            )

            # ----------------------------------------------
            # Recalculate current SHA-256
            # ----------------------------------------------

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

            # ----------------------------------------------
            # Record violation
            # ----------------------------------------------

            if not link_valid or not hash_valid:

                violation_records += 1

                if len(first_violations) < 10:

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
                            f"{verified_records}: "
                            + ", ".join(reasons)
                        )
                    )

            # The stored current hash is the expected
            # previous hash for the next physical row.
            expected_previous_hash = (
                stored_current_hash
            )

        reader_error = (
            reader.stderr.read()
            if reader.stderr
            else ""
        )

        reader_returncode = (
            reader.wait()
        )

        if reader_returncode != 0:

            raise RuntimeError(
                "Unable to read protected "
                "HDFS data:\n"
                + reader_error
            )

    # ======================================================
    # Record Count Security Check
    #
    # Detects insertion/deletion including a deletion
    # occurring at the end of the chain.
    # ======================================================

    record_count_valid = (
        verified_records
        == EXPECTED_RECORDS
    )

    if not record_count_valid:

        violation_records += 1

        first_violations.append(
            (
                "Record-count mismatch: "
                f"expected {EXPECTED_RECORDS}, "
                f"found {verified_records}"
            )
        )

    integrity_pass = (
        violation_records == 0
        and record_count_valid
    )

    return {
        "pass": integrity_pass,
        "verified_records": verified_records,
        "violations": violation_records,
        "final_chain_hash": expected_previous_hash,
        "details": first_violations
    }


# ==========================================================
# Experiment Header
# ==========================================================

print("=" * 72)
print("S1 - INTEGRITY VERIFICATION + PYSPARK PROCESSING")
print("=" * 72)

print(
    f"Strategy             : {STRATEGY}"
)

print(
    f"Dataset scale        : {DATASET_SCALE}"
)

print(
    f"Source table         : {TABLE}"
)

print(
    f"Expected records     : {EXPECTED_RECORDS}"
)

print(
    f"HDFS protected input : "
    f"{HDFS_INPUT_PATH}"
)

print(
    f"Hash algorithm       : "
    f"{HASH_ALGORITHM}"
)

print()


# ==========================================================
# Stage 1 - Integrity Verification
# ==========================================================

print("=" * 72)
print("STAGE 1 - HASH-CHAIN VERIFICATION")
print("=" * 72)

security_monitor = ResourceMonitor()

security_monitor.start()

verification_start = time.perf_counter()

try:

    verification = verify_hash_chain()

except Exception as exc:

    verification_end = time.perf_counter()

    security_monitor.stop()

    print()
    print(
        "ERROR: Integrity verification failed."
    )

    print(str(exc))

    print()
    print(
        "LOCAL MYSQL WRITE: BLOCKED"
    )

    sys.exit(1)

verification_end = time.perf_counter()

security_monitor.stop()

verification_time = (
    verification_end
    - verification_start
)

security_resources = (
    security_monitor.results()
)


# ==========================================================
# Security Decision
# ==========================================================

print()
print(
    f"Verified records      : "
    f"{verification['verified_records']}"
)

print(
    f"Integrity violations  : "
    f"{verification['violations']}"
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

        for detail in verification["details"]:
            print(f"  - {detail}")

    print()
    print("=" * 72)

    print(
        "SECURITY DECISION: BLOCK"
    )

    print(
        "Local MySQL write was NOT executed."
    )

    print("=" * 72)

    # Important:
    # Do NOT continue to Spark/MySQL after failure.
    sys.exit(2)


# ==========================================================
# Start Spark
#
# Spark startup is intentionally outside measured
# PySpark-processing time, matching the S0 methodology.
# ==========================================================

spark = (
    SparkSession.builder
    .appName(
        "CIPS-SRUDA-S1-Integrity-Verified"
    )
    .getOrCreate()
)

spark.sparkContext.setLogLevel("WARN")


# ==========================================================
# Protected HDFS Schema
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
print("STAGE 2 - PYSPARK PROCESSING")
print("=" * 72)

pipeline_monitor = ResourceMonitor()

pipeline_monitor.start()

pyspark_start = time.perf_counter()

try:

    protected_df = (
        spark.read
        .option("header", "false")
        .option(
            "timestampFormat",
            "yyyy-MM-dd HH:mm:ss.S"
        )
        .option(
            "mode",
            "FAILFAST"
        )
        .schema(protected_schema)
        .csv(HDFS_INPUT_PATH)
    )

    # Keep the same original analytical columns as S0.
    #
    # Hash columns are security metadata and are NOT
    # written into table_stock.
    output_df = protected_df.select(
        "id",
        "product_id",
        "purchasing_price",
        "quantity",
        "stock_date"
    )

    output_df = output_df.persist(
        StorageLevel.MEMORY_AND_DISK
    )

    # Force actual Spark processing.
    output_records = output_df.count()

except Exception as exc:

    pipeline_monitor.stop()

    spark.stop()

    print()
    print(
        "ERROR: PySpark processing failed."
    )

    print(str(exc))

    sys.exit(1)

pyspark_end = time.perf_counter()

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

    print()
    print(
        "ERROR: PySpark output record-count "
        "mismatch."
    )

    print(
        f"Expected : {EXPECTED_RECORDS}"
    )

    print(
        f"Actual   : {output_records}"
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
print("STAGE 3 - LOCAL MYSQL WRITE")
print("=" * 72)

mysql_start = time.perf_counter()

mysql_status = "FAILED"

try:

    (
        output_df.write
        .format("jdbc")
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
        .mode("append")
        .save()
    )

    mysql_status = "SUCCESS"

except Exception as exc:

    print()
    print(
        "ERROR: Local MySQL write failed."
    )

    print(str(exc))

mysql_end = time.perf_counter()

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
# HDFS Storage Size
# ==========================================================

hdfs_size_bytes = (
    get_hdfs_size_bytes()
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
    verification_time
    + pyspark_processing_time
    + mysql_write_time
)


# ==========================================================
# Duration-Weighted CPU / Memory
#
# Security verification:
#   verification_time
#
# Pipeline:
#   PySpark + MySQL write
# ==========================================================

pipeline_duration = (
    pyspark_processing_time
    + mysql_write_time
)

measured_duration = (
    verification_time
    + pipeline_duration
)

if measured_duration > 0:

    weighted_average_cpu = (
        (
            security_resources["avg_cpu"]
            * verification_time
        )
        +
        (
            pipeline_resources["avg_cpu"]
            * pipeline_duration
        )
    ) / measured_duration

    weighted_average_memory = (
        (
            security_resources["avg_memory"]
            * verification_time
        )
        +
        (
            pipeline_resources["avg_memory"]
            * pipeline_duration
        )
    ) / measured_duration

else:

    weighted_average_cpu = 0.0
    weighted_average_memory = 0.0


overall_peak_cpu = max(
    security_resources["peak_cpu"],
    pipeline_resources["peak_cpu"]
)

overall_peak_memory = max(
    security_resources["peak_memory"],
    pipeline_resources["peak_memory"]
)


# ==========================================================
# Final Status
# ==========================================================

if (
    verification["pass"]
    and mysql_status == "SUCCESS"
    and output_records == EXPECTED_RECORDS
):

    execution_status = "SUCCESS"
    final_returncode = 0

else:

    execution_status = "FAILED"
    final_returncode = 1


# ==========================================================
# Final Results
# ==========================================================

print()
print("=" * 72)
print("S1 - INTEGRITY + PYSPARK RESULT")
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
    f"Verified protected records            : "
    f"{verification['verified_records']}"
)

print(
    f"Output records                        : "
    f"{output_records}"
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
    f"Hash-chain verification time          : "
    f"{verification_time:.2f} seconds"
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
    f"HDFS protected storage size           : "
    f"{hdfs_size_mb:.4f} MB"
)

print()

# ----------------------------------------------------------
# Security Detail
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
    f"Final verified chain hash             : "
    f"{verification['final_chain_hash']}"
)

print("=" * 72)

print(
    "IMPORTANT FOR I1:"
)

print(
    "Additional S1 security-processing time ="
)

print(
    "Hash-chain generation time from Script 1"
)

print(
    "+"
)

print(
    f"Hash-chain verification time "
    f"({verification_time:.2f} seconds)"
)

print()

print(
    "Total S1 pipeline time ="
)

print(
    "Sqoop ingestion time"
)

print(
    "+ Hash-chain generation time"
)

print(
    f"+ Hash-chain verification time "
    f"({verification_time:.2f})"
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

sys.exit(final_returncode)
