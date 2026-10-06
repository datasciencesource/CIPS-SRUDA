import hashlib
import os
import subprocess
import sys
import threading
import time
from datetime import datetime

REMOTE_DB = "jdbc:mysql://69.175.69.34/sumrachna_hd"
USERNAME = "sumrachna_hd"
PASSWORD = os.getenv("REMOTE_DB_PASSWORD")
SOURCE_TABLE = os.getenv("SOURCE_TABLE")
HDFS_TARGET = "/security_lab/s1"
HDFS_STAGING = "/security_lab/s1_staging"
GENESIS_HASH = "GENESIS"

DATASETS = {
    "table_stock100": ("Small", 125),
    "table_stock20K": ("Medium", 24858),
    "table_stock4M": ("Large", 4248576),
}

if not PASSWORD or not SOURCE_TABLE or SOURCE_TABLE not in DATASETS:
    print("ERROR: Set REMOTE_DB_PASSWORD and a valid SOURCE_TABLE.")
    sys.exit(1)

DATASET_SCALE, EXPECTED_RECORDS = DATASETS[SOURCE_TABLE]
cpu_samples, memory_samples = [], []
stop_event = threading.Event()


def cpu_values():
    with open("/proc/stat") as f:
        values = list(map(float, f.readline().split()[1:9]))
    idle = values[3] + values[4]
    return sum(values), idle


def memory_percent():
    values = {}
    with open("/proc/meminfo") as f:
        for line in f:
            key, value = line.split(":", 1)
            values[key] = float(value.split()[0])
    return (values["MemTotal"] - values["MemAvailable"]) / values["MemTotal"] * 100


def monitor():
    previous_total, previous_idle = cpu_values()
    while not stop_event.wait(0.5):
        total, idle = cpu_values()
        if total > previous_total:
            cpu_samples.append((1 - (idle - previous_idle) / (total - previous_total)) * 100)
        memory_samples.append(memory_percent())
        previous_total, previous_idle = total, idle


def average(values):
    return sum(values) / len(values) if values else 0.0


def run_hdfs(args, check=False, capture=False):
    return subprocess.run(
        ["hdfs", "dfs", *args],
        check=check,
        capture_output=capture,
        text=True,
    )


def calculate_hash(previous_hash, row):
    return hashlib.sha256(f"{previous_hash}|{row}".encode()).hexdigest()


def hash_chain_dataset():
    start = time.perf_counter()
    previous_hash = GENESIS_HASH
    records = 0
    files = sorted(
        line.split()[-1]
        for line in run_hdfs(["-ls", HDFS_STAGING], capture=True).stdout.splitlines()
        if line.split() and line.split()[-1].split("/")[-1].startswith("part")
    )
    run_hdfs(["-rm", "-r", "-f", HDFS_TARGET], capture=True)
    run_hdfs(["-mkdir", "-p", HDFS_TARGET], check=True)

    for input_file in files:
        name = input_file.rsplit("/", 1)[-1]
        output_file = f"{HDFS_TARGET}/{name}"
        reader = subprocess.Popen(
            ["hdfs", "dfs", "-cat", input_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        writer = subprocess.Popen(
            ["hdfs", "dfs", "-put", "-", output_file],
            stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            for raw in reader.stdout:
                row = raw.rstrip("\r\n")
                if not row:
                    continue
                current_hash = calculate_hash(previous_hash, row)
                writer.stdin.write(f"{row},{previous_hash},{current_hash}\n")
                previous_hash = current_hash
                records += 1
        finally:
            reader.stdout.close()
            writer.stdin.close()
        reader_error = reader.stderr.read()
        writer_error = writer.stderr.read()
        if reader.wait() != 0:
            raise RuntimeError(reader_error)
        if writer.wait() != 0:
            raise RuntimeError(writer_error)

    if records != EXPECTED_RECORDS:
        raise RuntimeError(f"Expected {EXPECTED_RECORDS} records but hashed {records}")
    return records, previous_hash, time.perf_counter() - start


command = [
    "sqoop", "import", "--connect", REMOTE_DB,
    "--username", USERNAME, "--password", PASSWORD,
    "--table", SOURCE_TABLE, "--target-dir", HDFS_STAGING,
    "--delete-target-dir",
]

start_label = datetime.now().astimezone().isoformat(timespec="seconds")
thread = threading.Thread(target=monitor, daemon=True)
thread.start()
ingestion_start = time.perf_counter()
sqoop = subprocess.run(command)
s0_time = time.perf_counter() - ingestion_start
stop_event.set()
thread.join()

status = "SUCCESS"
error = "N/A"
protected_records = 0
final_hash = "N/A"
s1_hash_time = 0.0
try:
    if sqoop.returncode != 0:
        raise RuntimeError("Sqoop ingestion failed")
    protected_records, final_hash, s1_hash_time = hash_chain_dataset()
except Exception as exc:
    status = "FAILED"
    error = str(exc)

end_label = datetime.now().astimezone().isoformat(timespec="seconds")
s1_total = s0_time + s1_hash_time
size_result = run_hdfs(["-du", "-s", HDFS_TARGET], capture=True) if status == "SUCCESS" else None
try:
    storage_mb = int(size_result.stdout.split()[0]) / (1024 ** 2)
except (AttributeError, ValueError, IndexError):
    storage_mb = 0.0

print("=" * 72)
print("S1 - SQOOP INGESTION + HASH-CHAIN RESULT")
print("=" * 72)
print("Laboratory environment                : S1")
print("Strategy under test                   : S1")
print(f"Dataset scale                         : {DATASET_SCALE}")
print(f"Source table                          : {SOURCE_TABLE}")
print(f"Expected records                      : {EXPECTED_RECORDS}")
print(f"Workflow start time                   : {start_label}")
print(f"Workflow end time                     : {end_label}")
print(f"Execution status                      : {status}")
print(f"S0-Script-1 ingestion time            : {s0_time:.2f} seconds")
print(f"S1 hash-chain processing time         : {s1_hash_time:.2f} seconds")
print(f"S1-Script-1 cumulative time           : {s1_total:.2f} seconds")
print(f"Protected records                     : {protected_records}")
print(f"HDFS output verified                  : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"Average CPU utilization               : {average(cpu_samples):.2f}%")
print(f"Peak CPU utilization                  : {max(cpu_samples) if cpu_samples else 0.0:.2f}%")
print(f"Average memory utilization            : {average(memory_samples):.2f}%")
print(f"Peak memory utilization               : {max(memory_samples) if memory_samples else 0.0:.2f}%")
print(f"HDFS storage size                     : {storage_mb:.4f} MB")
print("Retry required                        : NO")
print("Number of retries                     : 0")
print(f"Error / failure message               : {error}")
print(f"Abnormal condition observed           : {'NO' if status == 'SUCCESS' else 'YES'}")
print("S0 indicators                        : RECORDED")
print("S1 indicators                        : RECORDED")
print("S2/S3 indicators                     : N/A - not tested")
print(f"Hash algorithm                        : SHA-256")
print(f"Genesis previous hash                 : {GENESIS_HASH}")
print(f"Final chain hash                      : {final_hash}")
print("=" * 72)
sys.exit(0 if status == "SUCCESS" else 1)
