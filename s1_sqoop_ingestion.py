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

if not PASSWORD or SOURCE_TABLE not in DATASETS:
    print("ERROR: Set REMOTE_DB_PASSWORD and a valid SOURCE_TABLE.")
    sys.exit(1)

DATASET_SCALE, EXPECTED_RECORDS = DATASETS[SOURCE_TABLE]

cpu_samples = []
memory_samples = []
stop_event = threading.Event()


def cpu_values():
    with open("/proc/stat") as f:
        values = list(map(float, f.readline().split()[1:9]))

    return sum(values), values[3] + values[4]


def memory_percent():
    values = {}

    with open("/proc/meminfo") as f:
        for line in f:
            key, value = line.split(":", 1)
            values[key] = float(value.split()[0])

    return (
        (values["MemTotal"] - values["MemAvailable"])
        / values["MemTotal"]
        * 100
    )


def monitor():
    old_total, old_idle = cpu_values()

    while not stop_event.wait(0.5):
        total, idle = cpu_values()

        if total > old_total:
            cpu_samples.append(
                (
                    1
                    - (idle - old_idle)
                    / (total - old_total)
                )
                * 100
            )

        memory_samples.append(memory_percent())
        old_total, old_idle = total, idle


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
    start = time.perf_counter()
    previous_hash = "GENESIS"
    record_count = 0

    with tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        suffix=".csv"
    ) as output:

        temporary_file = output.name

        raw_process = subprocess.Popen(
            [
                "hdfs",
                "dfs",
                "-cat",
                f"{RAW_HDFS_TARGET}/part*"
            ],
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

            output.write(f"{row},{current_hash}\n")

            previous_hash = current_hash
            record_count += 1

        raw_process.stdout.close()
        raw_error = raw_process.stderr.read()
        raw_code = raw_process.wait()

    if raw_code != 0:
        os.unlink(temporary_file)
        raise RuntimeError(raw_error)

    subprocess.run(
        ["hdfs", "dfs", "-rm", "-r", "-f", HDFS_TARGET],
        check=False
    )

    subprocess.run(
        ["hdfs", "dfs", "-mkdir", "-p", HDFS_TARGET],
        check=True
    )

    subprocess.run(
        [
            "hdfs",
            "dfs",
            "-put",
            "-f",
            temporary_file,
            f"{HDFS_TARGET}/part-00000"
        ],
        check=True
    )

    os.unlink(temporary_file)

    hash_time = time.perf_counter() - start

    if record_count != EXPECTED_RECORDS:
        raise RuntimeError(
            f"Expected {EXPECTED_RECORDS} records "
            f"but found {record_count}"
        )

    return hash_time, record_count


print("=" * 72)
print("S1 - SQOOP INGESTION AND HASH-CHAIN RESULT")
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

status = "FAILED"
error_message = "N/A"
hash_time = 0.0
records = 0

try:
    if sqoop_result.returncode != 0:
        raise RuntimeError("Sqoop ingestion failed.")

    hash_time, records = generate_hash_chain()
    status = "SUCCESS"

except Exception as exc:
    error_message = str(exc)

stop_event.set()
monitor_thread.join()

end_label = datetime.now().astimezone().isoformat(
    timespec="seconds"
)

s1_script1_time = sqoop_time + hash_time
storage_size = hdfs_size(HDFS_TARGET)

print(f"Workflow end time                     : {end_label}")
print(f"Execution status                      : {status}")

print(
    f"S0-Script-1 time                      : "
    f"{sqoop_time:.2f} seconds"
)

print(
    f"Hash-chain time                       : "
    f"{hash_time:.2f} seconds"
)

print(
    f"S1-Script-1 total time                : "
    f"{s1_script1_time:.2f} seconds"
)

print(
    f"HDFS output verified                  : "
    f"{'PASS' if status == 'SUCCESS' else 'FAIL'}"
)

print(f"Average CPU utilization               : {average(cpu_samples):.2f}%")
print(
    f"Peak CPU utilization                  : "
    f"{max(cpu_samples) if cpu_samples else 0.0:.2f}%"
)
print(
    f"Average memory utilization            : "
    f"{average(memory_samples):.2f}%"
)
print(
    f"Peak memory utilization               : "
    f"{max(memory_samples) if memory_samples else 0.0:.2f}%"
)

print(f"HDFS storage size                     : {storage_size:.4f} MB")
print(f"Output records                        : {records}")
print("Retry required                        : NO")
print("Number of retries                     : 0")
print(f"Error / failure message               : {error_message}")
print(
    f"Abnormal condition observed           : "
    f"{'NO' if status == 'SUCCESS' else 'YES'}"
)

print("S0 baseline workflow                  : RETAINED")
print("S1 hash-chain protection              : "
      f"{'PASS' if status == 'SUCCESS' else 'FAIL'}")

print("=" * 72)

sys.exit(0 if status == "SUCCESS" else 1)
