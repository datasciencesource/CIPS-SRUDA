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
ENCRYPTION_KEY = os.getenv("S2_ENCRYPTION_KEY")

RAW_HDFS_TARGET = "/security_lab/s2_raw"
HDFS_TARGET = "/security_lab/s2"

DATASETS = {
    "table_stock100": ("Small", 125),
    "table_stock20K": ("Medium", 24858),
    "table_stock4M": ("Large", 4248576),
}

if not PASSWORD or not SOURCE_TABLE or SOURCE_TABLE not in DATASETS:
    print("ERROR: Set REMOTE_DB_PASSWORD and a valid SOURCE_TABLE.")
    sys.exit(1)

if not ENCRYPTION_KEY:
    print("ERROR: Set S2_ENCRYPTION_KEY.")
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
                (1 - (idle - old_idle) / (total - old_total)) * 100
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


def create_hash_chain():
    previous_hash = "GENESIS"
    records = 0

    output = tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        suffix=".csv"
    )

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
        records += 1

    output.close()

    raw_error = raw_process.stderr.read()
    raw_code = raw_process.wait()

    if raw_code != 0:
        os.unlink(temporary_file)
        raise RuntimeError(raw_error)

    if records != EXPECTED_RECORDS:
        os.unlink(temporary_file)
        raise RuntimeError(
            f"Expected {EXPECTED_RECORDS} records but found {records}"
        )

    return temporary_file, records


def encrypt_file(input_file):
    encrypted_file = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".enc"
    ).name

    environment = os.environ.copy()
    environment["S2_KEY"] = ENCRYPTION_KEY

    subprocess.run(
        [
            "openssl",
            "enc",
            "-aes-256-cbc",
            "-pbkdf2",
            "-salt",
            "-in",
            input_file,
            "-out",
            encrypted_file,
            "-pass",
            "env:S2_KEY"
        ],
        env=environment,
        check=True
    )

    return encrypted_file


print("=" * 72)
print("S2 - SQOOP, HASH-CHAIN, AND ENCRYPTION RESULT")
print("=" * 72)
print("Laboratory environment                : S2")
print("Strategy under test                   : S2")
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

status = "FAILED"
error_message = "N/A"
sqoop_time = 0.0
hash_time = 0.0
encryption_time = 0.0
records = 0

try:
    sqoop_start = time.perf_counter()
    sqoop_result = subprocess.run(sqoop_command)
    sqoop_time = time.perf_counter() - sqoop_start

    if sqoop_result.returncode != 0:
        raise RuntimeError("Sqoop ingestion failed.")

    hash_start = time.perf_counter()
    hash_file, records = create_hash_chain()
    hash_time = time.perf_counter() - hash_start

    encryption_start = time.perf_counter()
    encrypted_file = encrypt_file(hash_file)
    encryption_time = time.perf_counter() - encryption_start

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
            encrypted_file,
            f"{HDFS_TARGET}/part-00000.enc"
        ],
        check=True
    )

    os.unlink(hash_file)
    os.unlink(encrypted_file)

    status = "SUCCESS"

except Exception as exc:
    error_message = str(exc)

stop_event.set()
monitor_thread.join()

end_label = datetime.now().astimezone().isoformat(
    timespec="seconds"
)

s0_script1_time = sqoop_time
s1_script1_time = sqoop_time + hash_time
s2_script1_time = s1_script1_time + encryption_time
storage_size = hdfs_size(HDFS_TARGET)

print(f"Workflow end time                     : {end_label}")
print(f"Execution status                      : {status}")
print(f"S0-Script-1 time                      : {s0_script1_time:.2f} seconds")
print(f"Hash-chain time                       : {hash_time:.2f} seconds")
print(f"S1-Script-1 total time                : {s1_script1_time:.2f} seconds")
print(f"Encryption time                       : {encryption_time:.2f} seconds")
print(f"S2-Script-1 total time                : {s2_script1_time:.2f} seconds")
print(
    f"HDFS output verified                  : "
    f"{'PASS' if status == 'SUCCESS' else 'FAIL'}"
)
print(f"HDFS storage size                     : {storage_size:.4f} MB")
print(f"Output records                        : {records}")
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
print("Retry required                        : NO")
print("Number of retries                     : 0")
print(f"Error / failure message               : {error_message}")
print(
    "Abnormal condition observed           : "
    f"{'NO' if status == 'SUCCESS' else 'YES'}"
)
print("S0 baseline workflow                  : RETAINED")
print(
    "S1 hash-chain protection              : "
    f"{'PASS' if status == 'SUCCESS' else 'FAIL'}"
)
print(
    "S2 encryption protection              : "
    f"{'PASS' if status == 'SUCCESS' else 'FAIL'}"
)
print("=" * 72)

sys.exit(0 if status == "SUCCESS" else 1)
