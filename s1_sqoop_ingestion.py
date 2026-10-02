import hashlib
import os
import subprocess
import sys
import threading
import time

# ==========================================================
# S1 - Integrity-Protected Sqoop Ingestion
# ==========================================================
#
# Remote MySQL
#      ↓
# Sqoop
#      ↓
# Temporary HDFS staging
#      ↓
# SHA-256 hash-chain generation
#      ↓
# /security_lab/s1/part*
#
# Final protected row:
#
# id,product_id,purchasing_price,quantity,stock_date,
# previous_hash,current_hash
#
# IMPORTANT:
# This script DOES NOT touch /security_lab/s0.
# ==========================================================

STRATEGY = "S1"

# ==========================================================
# Remote Database Configuration
# ==========================================================

REMOTE_DB = "jdbc:mysql://69.175.69.34/sumrachna_hd"
USERNAME = "sumrachna_hd"

PASSWORD = os.getenv("REMOTE_DB_PASSWORD")
TABLE = os.getenv("SOURCE_TABLE")

# ==========================================================
# HDFS Paths - S1 ONLY
# ==========================================================

# Temporary unprotected Sqoop output
HDFS_STAGING = "/security_lab/s1_staging"

# Temporary protected build
HDFS_BUILD = "/security_lab/s1_build"

# Final protected S1 dataset
HDFS_TARGET = "/security_lab/s1"

# ==========================================================
# Integrity Configuration
# ==========================================================

HASH_ALGORITHM = "SHA-256"
GENESIS_HASH = "GENESIS"

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
# Validate Environment
# ==========================================================

if not PASSWORD:
    print("ERROR: REMOTE_DB_PASSWORD is not set.")
    print("Run:")
    print("export REMOTE_DB_PASSWORD='your_password'")
    sys.exit(1)

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
    print()
    print("Allowed experimental tables:")
    print("  table_stock100 = Small")
    print("  table_stock20K = Medium")
    print("  table_stock4M  = Large")
    sys.exit(1)

DATASET_SCALE = DATASETS[TABLE]["scale"]
EXPECTED_RECORDS = DATASETS[TABLE]["expected_records"]

# ==========================================================
# Resource Monitoring
# ==========================================================

cpu_samples = []
memory_samples = []
stop_monitoring = threading.Event()


def get_cpu_values():
    with open("/proc/stat", "r") as f:
        values = list(
            map(float, f.readline().split()[1:9])
        )

    user, nice, system, idle, iowait, irq, softirq, steal = values

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


def get_memory_percent():
    meminfo = {}

    with open("/proc/meminfo", "r") as f:
        for line in f:
            key, value = line.split(":", 1)
            meminfo[key] = float(
                value.strip().split()[0]
            )

    total = meminfo["MemTotal"]
    available = meminfo["MemAvailable"]

    return ((total - available) / total) * 100


def monitor_resources():
    previous_total, previous_idle = get_cpu_values()

    while not stop_monitoring.wait(0.5):
        current_total, current_idle = get_cpu_values()

        total_delta = (
            current_total - previous_total
        )

        idle_delta = (
            current_idle - previous_idle
        )

        if total_delta > 0:
            cpu_percent = (
                (total_delta - idle_delta)
                / total_delta
            ) * 100

            cpu_samples.append(cpu_percent)

        memory_samples.append(
            get_memory_percent()
        )

        previous_total = current_total
        previous_idle = current_idle


# ==========================================================
# HDFS Utility Functions
# ==========================================================

def hdfs_remove(path):
    """
    Remove an HDFS path if it exists.

    Used ONLY for S1 paths.
    """

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


def get_hdfs_size_bytes(path):
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
            result.stdout.split()[0]
        )

    except (ValueError, IndexError):
        return 0


def get_hdfs_part_files(path):
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
            f"Unable to list HDFS path: {path}"
        )

    part_files = []

    for line in result.stdout.splitlines():
        fields = line.split()

        if not fields:
            continue

        candidate = fields[-1]

        basename = os.path.basename(
            candidate
        )

        if basename.startswith("part"):
            part_files.append(candidate)

    # Deterministic part-file order
    part_files.sort()

    if not part_files:
        raise RuntimeError(
            f"No Sqoop part files found in {path}"
        )

    return part_files


# ==========================================================
# Reset Previous S1 Data
# ==========================================================

def reset_s1_environment():
    """
    Clean only S1 paths.

    /security_lab/s0 is intentionally NOT touched.
    """

    print("=" * 72)
    print("RESETTING PREVIOUS S1 HDFS DATA")
    print("=" * 72)

    hdfs_remove(HDFS_TARGET)
    hdfs_remove(HDFS_STAGING)
    hdfs_remove(HDFS_BUILD)

    print(f"Removed previous S1 target  : {HDFS_TARGET}")
    print(f"Removed previous staging    : {HDFS_STAGING}")
    print(f"Removed previous build      : {HDFS_BUILD}")
    print()


# ==========================================================
# Hash-Chain Function
# ==========================================================

def calculate_current_hash(
    previous_hash,
    row_data
):
    """
    BIBDIS-style hash chaining:

    current_hash =
        SHA256(previous_hash + "|" + row_data)
    """

    hash_input = (
        previous_hash
        + "|"
        + row_data
    )

    return hashlib.sha256(
        hash_input.encode("utf-8")
    ).hexdigest()


# ==========================================================
# Generate S1 Protected Dataset
# ==========================================================

def generate_protected_dataset():
    """
    Input row from Sqoop:

    id,product_id,purchasing_price,quantity,stock_date

    Output S1 row:

    id,product_id,purchasing_price,quantity,stock_date,
    previous_hash,current_hash

    First row:

    previous_hash = GENESIS

    Next rows:

    previous_hash =
        previous row's current_hash
    """

    security_start = time.perf_counter()

    part_files = get_hdfs_part_files(
        HDFS_STAGING
    )

    hdfs_mkdir(HDFS_BUILD)

    previous_hash = GENESIS_HASH

    protected_records = 0

    # ------------------------------------------------------
    # Process each Sqoop part file
    # ------------------------------------------------------

    for input_part in part_files:

        part_name = os.path.basename(
            input_part
        )

        output_part = (
            f"{HDFS_BUILD}/{part_name}"
        )

        print(
            f"Hash protecting: {part_name}"
        )

        # Read raw rows directly from HDFS
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

        # Write protected rows directly to HDFS
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

                # Preserve original Sqoop representation.
                # Only remove newline characters.
                row_data = raw_line.rstrip(
                    "\r\n"
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
                    f"{current_hash}\n"
                )

                writer.stdin.write(
                    protected_row
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

        reader_returncode = reader.wait()
        writer_returncode = writer.wait()

        if reader_returncode != 0:
            raise RuntimeError(
                "Failed to read HDFS staging file:\n"
                + reader_error
            )

        if writer_returncode != 0:
            raise RuntimeError(
                "Failed to write protected HDFS file:\n"
                + writer_error
            )

    # ======================================================
    # Verify Record Count
    # ======================================================

    if protected_records != EXPECTED_RECORDS:
        raise RuntimeError(
            "Protected record-count mismatch: "
            f"expected {EXPECTED_RECORDS}, "
            f"generated {protected_records}."
        )

    # ======================================================
    # Activate S1 Protected Dataset
    # ======================================================

    result = subprocess.run(
        [
            "hdfs",
            "dfs",
            "-mv",
            HDFS_BUILD,
            HDFS_TARGET
        ]
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Unable to activate protected S1 dataset."
        )

    security_end = time.perf_counter()

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
# Remote MySQL -> Temporary HDFS
# ==========================================================

sqoop_command = [
    "sqoop",
    "import",
    "--connect", REMOTE_DB,
    "--username", USERNAME,
    "--password", PASSWORD,
    "--table", TABLE,
    "--target-dir", HDFS_STAGING,
    "--delete-target-dir"
]

# ==========================================================
# Experiment Header
# ==========================================================

print("=" * 72)
print("S1 - INTEGRITY-PROTECTED SQOOP INGESTION")
print("=" * 72)

print(
    f"Strategy          : {STRATEGY}"
)

print(
    f"Dataset scale     : {DATASET_SCALE}"
)

print(
    f"Source table      : {TABLE}"
)

print(
    f"Expected records  : {EXPECTED_RECORDS}"
)

print(
    f"Staging path      : {HDFS_STAGING}"
)

print(
    f"Final HDFS target : {HDFS_TARGET}"
)

print(
    f"Hash algorithm    : {HASH_ALGORITHM}"
)

print(
    f"Genesis hash      : {GENESIS_HASH}"
)

print()

# ==========================================================
# Reset S1 Only
#
# This reset is experimental preparation and is NOT
# included in the performance timing.
# ==========================================================

reset_s1_environment()

# ==========================================================
# Start Resource Monitoring
# ==========================================================

monitor_thread = threading.Thread(
    target=monitor_resources,
    daemon=True
)

monitor_thread.start()

sqoop_returncode = 1

security_status = "NOT RUN"

protected_records = 0

final_chain_hash = "N/A"

security_processing_time = 0.0

# ==========================================================
# Stage 1 - Sqoop Ingestion
#
# Performance boundary kept comparable with S0:
#
# Remote MySQL -> HDFS
# ==========================================================

print("=" * 72)
print("STAGE 1 - SQOOP INGESTION")
print("=" * 72)

sqoop_start = time.perf_counter()

try:

    sqoop_result = subprocess.run(
        sqoop_command
    )

    sqoop_returncode = (
        sqoop_result.returncode
    )

except Exception as exc:

    print(
        f"ERROR: Sqoop execution failed: {exc}"
    )

    sqoop_returncode = 1

sqoop_end = time.perf_counter()

sqoop_ingestion_time = (
    sqoop_end - sqoop_start
)

# ==========================================================
# Stage 2 - SHA-256 Hash-Chain Generation
# ==========================================================

if sqoop_returncode == 0:

    print()
    print("=" * 72)
    print(
        "STAGE 2 - SHA-256 HASH-CHAIN GENERATION"
    )
    print("=" * 72)

    try:

        (
            protected_records,
            final_chain_hash,
            security_processing_time
        ) = generate_protected_dataset()

        security_status = "SUCCESS"

    except Exception as exc:

        security_status = "FAILED"

        print()
        print(
            "ERROR: S1 integrity protection failed."
        )

        print(str(exc))

        # Remove incomplete S1 protected output.
        hdfs_remove(HDFS_TARGET)
        hdfs_remove(HDFS_BUILD)

else:

    print()
    print(
        "Security processing skipped because "
        "Sqoop ingestion failed."
    )

# ==========================================================
# Remove Temporary Unprotected Staging
# ==========================================================

# The temporary unprotected S1 data is always removed.
# /security_lab/s0 is NOT touched.

hdfs_remove(HDFS_STAGING)

# ==========================================================
# Stop Resource Monitoring
# ==========================================================

stop_monitoring.set()

monitor_thread.join()

# ==========================================================
# Resource Results
# ==========================================================

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

# ==========================================================
# HDFS Protected Storage Size
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
# Final Execution Status
# ==========================================================

if (
    sqoop_returncode == 0
    and security_status == "SUCCESS"
    and protected_records == EXPECTED_RECORDS
):

    execution_status = "SUCCESS"
    final_returncode = 0

else:

    execution_status = "FAILED"
    final_returncode = 1

# ==========================================================
# Script 1 Performance
# ==========================================================

script1_total_time = (
    sqoop_ingestion_time
    + security_processing_time
)

# ==========================================================
# Final Results
# ==========================================================

print()
print("=" * 72)
print("S1 - SQOOP + INTEGRITY PROTECTION RESULT")
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
    f"Protected records                     : "
    f"{protected_records}"
)

print(
    f"Execution status                      : "
    f"{execution_status}"
)

print(
    f"Integrity-protection status           : "
    f"{security_status}"
)

print(
    f"Sqoop ingestion time "
    f"(Remote MySQL -> HDFS staging)        : "
    f"{sqoop_ingestion_time:.2f} seconds"
)

print(
    f"Hash-chain generation time            : "
    f"{security_processing_time:.2f} seconds"
)

print(
    f"Additional security-processing time   : "
    f"{security_processing_time:.2f} seconds"
)

print(
    f"Script 1 total measured time          : "
    f"{script1_total_time:.2f} seconds"
)

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
    f"HDFS protected storage size           : "
    f"{hdfs_size_mb:.4f} MB"
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
    f"Final chain hash                      : "
    f"{final_chain_hash}"
)

print(
    f"Final protected dataset               : "
    f"{HDFS_TARGET}/part*"
)

print("=" * 72)

if execution_status == "SUCCESS":

    print(
        "S1 protected dataset created successfully."
    )

    print(
        "Temporary unprotected S1 staging data "
        "has been removed."
    )

    print(
        "/security_lab/s0 was NOT modified "
        "by this script."
    )

else:

    print(
        "S1 ingestion/integrity protection FAILED."
    )

print("=" * 72)

sys.exit(final_returncode)
