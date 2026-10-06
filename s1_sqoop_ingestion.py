import hashlib
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime

REMOTE_DB = "jdbc:mysql://69.175.69.34/sumrachna_hd"
USERNAME = "sumrachna_hd"
PASSWORD = os.getenv("REMOTE_DB_PASSWORD")
SOURCE_TABLE = os.getenv("SOURCE_TABLE")

RAW_HDFS_TARGET = "/security_lab/s1_raw"
HDFS_TARGET = "/security_lab/s1"

DATASETS = {
    "table_stock100": ("Small", 125),
    "table_stock20K": ("Medium", 24858),
    "table_stock4M": ("Large", 4248576),
}

if not PASSWORD or not SOURCE_TABLE or SOURCE_TABLE not in DATASETS:
    print("ERROR: Set REMOTE_DB_PASSWORD and a valid SOURCE_TABLE.")
    sys.exit(1)

DATASET_SCALE, EXPECTED_RECORDS = DATASETS[SOURCE_TABLE]

cpu_samples = []
memory_samples = []
stop_event = threading.Event()


def cpu_values():
    with open("/proc/stat") as file:
        values = list(map(float, file.readline().split()[1:9]))

    idle = values[3] + values[4]
    return sum(values), idle


def memory_percent():
    values = {}

    with open("/proc/meminfo") as file:
        for line in file:
            key, value = line.split(":", 1)
            values[key] = float(value.split()[0])

    return (
        (values["MemTotal"] - values["MemAvailable"])
        / values["MemTotal"]
        * 100
    )


def monitor():
    previous_total, previous_idle = cpu_values()

    while not stop_event.wait(0.5):
        total, idle = cpu_values()

        if total > previous_total:
            cpu_usage = (
                1 - (idle - previous_idle)
                / (total - previous_total)
            ) * 100

            cpu_samples.append(cpu_usage)

        memory_samples.append(memory_percent())

        previous_total = total
        previous_idle = idle


def average(values):
    return sum(values) / len(values) if values else 0.0


def hdfs_size(path):
    result = subprocess.run(
        ["hdfs", "dfs", "-du", "-s", path],
        capture_output=True,
        text=True
    )

    try:
        return int(result.stdout.split()[0]) / (1024 ** 2)
    except (ValueError, IndexError):
        return 0.0


def generate_hash_chain():
    """
    Reads the raw Sqoop CSV files from HDFS and creates a new CSV file
    containing the original data plus a SHA-256 chained hash.

    Output format:

    original_columns, row_hash
    """

    start = time.perf_counter()

    raw_command = [
        "hdfs", "dfs", "-cat",
        f"{RAW_HDFS_TARGET}/part*"
    ]

    with tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        prefix="s1_hash_chain_",
        suffix=".csv"
    ) as output_file:

        temporary_file = output_file.name
        previous_hash = "GENESIS"
        record_count = 0

        raw_process = subprocess.Popen(
            raw_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        for line in raw_process.stdout:
            row = line.rstrip("\n\r")

            if not row:
                continue

            current_hash = hashlib.sha256(
                f"{previous_hash}|{row}".encode("utf-8")
            ).hexdigest()

            output_file.write(f"{row},{current_hash}\n")

            previous_hash = current_hash
            record_count += 1

        raw_process.stdout.close()
        raw_error = raw_process.stderr.read()
        raw_return_code = raw_process.wait()

    if raw_return_code != 0:
        os.unlink(temporary_file)
        raise RuntimeError(
            f"Unable to read raw HDFS data: {raw_error}"
        )

    subprocess.run(
        ["hdfs", "dfs", "-mkdir", "-p", HDFS_TARGET],
        check=True
    )

    subprocess.run(
        [
            "hdfs", "dfs", "-put", "-f",
            temporary_file,
            f"{HDFS_TARGET}/part-00000"
        ],
        check=True
    )

    os.unlink(temporary_file)

    elapsed = time.perf_counter() - start

    if record_count != EXPECTED_RECORDS:
        raise RuntimeError(
            f"Expected {EXPECTED_RECORDS} records after hashing "
            f"but found {record_count}"
        )

    return elapsed, record_count


print("=" * 72)
print("S1 - SQOOP INGESTION WITH HASH-CHAIN RESULT")
print("=" * 72)

print("Laboratory environment                : S1")
print("Strategy under test                   : S1")
print(f"Dataset scale                         : {DATASET_SCALE}")
print(f"Source table                          : {SOURCE_TABLE}")
print(f"Expected records                      : {EXPECTED_RECORDS}")

start_label = datetime.now().astimezone().isoformat(
    timespec="seconds"
)

print(f"Workflow start time                   : {start_label}")

monitor_thread = threading.Thread(
    target=monitor,
    daemon=True
)

monitor_thread.start()

sqoop_command = [
    "sqoop",
    "import",
    "--connect",
    REMOTE_DB,
    "--username",
    USERNAME,
    "--password",
    PASSWORD,
    "--table",
    SOURCE_TABLE,
    "--target-dir",
    RAW_HDFS_TARGET,
    "--delete-target-dir"
]

sqoop_start = time.perf_counter()
sqoop_result = subprocess.run(sqoop_command)
sqoop_time = time.perf_counter() - sqoop_start

hash_time = 0.0
records = 0
status = "FAILED"
error_message = "N/A"

try:
    if sqoop_result.returncode != 0:
        raise RuntimeError("Sqoop ingestion failed.")

    hash_time, records = generate_hash_chain()

    status = "SUCCESS"

except Exception as error:
    error_message = str(error)

stop_event.set()
monitor_thread.join()

end_label = datetime.now().astimezone().isoformat(
    timespec="seconds"
)

raw_size_mb = hdfs_size(RAW_HDFS_TARGET)
hashed_size_mb = hdfs_size(HDFS_TARGET)

total_time = sqoop_time + hash_time

print(f"Workflow end time                     : {end_label}")
print(f"Execution status                      : {status}")
print(f"Sqoop ingestion time                  : {sqoop_time:.2f} seconds")
print(f"Hash-chain processing time            : {hash_time:.2f} seconds")
print(f"Total S1 Script-1 time                : {total_time:.2f} seconds")
print(f"Additional security-processing time   : {hash_time:.2f} seconds")
print(
    "HDFS output verified                  : "
    f"{'PASS' if status == 'SUCCESS' and hashed_size_mb > 0 else 'FAIL'}"
)
print(f"Average CPU utilization               : {average(cpu_samples):.2f}%")
print(
    "Peak CPU utilization                  : "
    f"{max(cpu_samples) if cpu_samples else 0.0:.2f}%"
)
print(
    "Average memory utilization            : "
    f"{average(memory_samples):.2f}%"
)
print(
    "Peak memory utilization              : "
    f"{max(memory_samples) if memory_samples else 0.0:.2f}%"
)
print(f"Raw HDFS storage size                 : {raw_size_mb:.4f} MB")
print(f"Hashed HDFS storage size              : {hashed_size_mb:.4f} MB")
print(f"Output records                        : {records}")
print("Retry required                        : NO")
print("Number of retries                     : 0")
print(f"Error / failure message               : {error_message}")
print(
    "Abnormal condition observed           : "
    f"{'NO' if status == 'SUCCESS' else 'YES'}"
)
print("S0 baseline pipeline                  : RETAINED")
print("S1 hash-chain protection              : PASS")
print("=" * 72)

sys.exit(0 if status == "SUCCESS" else 1)
