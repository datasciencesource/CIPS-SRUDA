import os
import subprocess
import sys
import threading
import time

# =====================================
# S0 - Sqoop Ingestion Configuration
# =====================================

REMOTE_DB = "jdbc:mysql://69.175.69.34/sumrachna_hd"
USERNAME = "sumrachna_hd"
PASSWORD = os.getenv("REMOTE_DB_PASSWORD")

TABLE = "table_stock100"
HDFS_TARGET = "/security_lab/s0"

# =====================================
# Check Credential
# =====================================

if not PASSWORD:
    print("ERROR: REMOTE_DB_PASSWORD is not set.")
    print("Run:")
    print("export REMOTE_DB_PASSWORD='your_password'")
    sys.exit(1)

# =====================================
# Resource Monitoring
# =====================================

cpu_samples = []
memory_samples = []
stop_monitoring = threading.Event()


def get_cpu_values():
    with open("/proc/stat", "r") as f:
        values = list(map(float, f.readline().split()[1:9]))

    user, nice, system, idle, iowait, irq, softirq, steal = values

    idle_total = idle + iowait
    active_total = user + nice + system + irq + softirq + steal
    total = idle_total + active_total

    return total, idle_total


def get_memory_percent():
    meminfo = {}

    with open("/proc/meminfo", "r") as f:
        for line in f:
            key, value = line.split(":", 1)
            meminfo[key] = float(value.strip().split()[0])

    total = meminfo["MemTotal"]
    available = meminfo["MemAvailable"]

    return ((total - available) / total) * 100


def monitor_resources():
    previous_total, previous_idle = get_cpu_values()

    while not stop_monitoring.wait(0.5):

        current_total, current_idle = get_cpu_values()

        total_delta = current_total - previous_total
        idle_delta = current_idle - previous_idle

        if total_delta > 0:
            cpu_percent = (
                (total_delta - idle_delta) / total_delta
            ) * 100

            cpu_samples.append(cpu_percent)

        memory_samples.append(get_memory_percent())

        previous_total = current_total
        previous_idle = current_idle


monitor_thread = threading.Thread(
    target=monitor_resources,
    daemon=True
)

# =====================================
# Sqoop Import
# =====================================

command = [
    "sqoop",
    "import",
    "--connect", REMOTE_DB,
    "--username", USERNAME,
    "--password", PASSWORD,
    "--table", TABLE,
    "--target-dir", HDFS_TARGET,
    "--delete-target-dir"
]

print("=" * 60)
print("S0 - SQOOP INGESTION")
print("=" * 60)

print(f"Source table : {TABLE}")
print(f"HDFS target  : {HDFS_TARGET}")
print()

# =====================================
# Start Measurement
# =====================================

monitor_thread.start()

start_time = time.time()

try:
    result = subprocess.run(command)

finally:
    end_time = time.time()

    stop_monitoring.set()
    monitor_thread.join()

ingestion_time = end_time - start_time

# =====================================
# Resource Results
# =====================================

average_cpu = (
    sum(cpu_samples) / len(cpu_samples)
    if cpu_samples else 0.0
)

peak_cpu = (
    max(cpu_samples)
    if cpu_samples else 0.0
)

average_memory = (
    sum(memory_samples) / len(memory_samples)
    if memory_samples else 0.0
)

peak_memory = (
    max(memory_samples)
    if memory_samples else 0.0
)

# =====================================
# HDFS Storage Size
# =====================================

hdfs_size_bytes = 0

if result.returncode == 0:

    size_result = subprocess.run(
        ["hdfs", "dfs", "-du", "-s", HDFS_TARGET],
        capture_output=True,
        text=True
    )

    if size_result.returncode == 0:

        try:
            hdfs_size_bytes = int(
                size_result.stdout.split()[0]
            )

        except (ValueError, IndexError):
            hdfs_size_bytes = 0


hdfs_size_mb = hdfs_size_bytes / (1024 ** 2)
hdfs_size_gb = hdfs_size_bytes / (1024 ** 3)

# =====================================
# Result
# =====================================

print()
print("=" * 60)
print("S0 - SQOOP INGESTION RESULT")
print("=" * 60)

if result.returncode == 0:
    print("Execution status        : SUCCESS")
else:
    print("Execution status        : FAILED")

print(
    f"Sqoop ingestion time    : "
    f"{ingestion_time:.2f} seconds"
)

print(
    "HDFS storage/write time : "
    "Included in Sqoop ingestion"
)

print(
    f"Average CPU utilization : "
    f"{average_cpu:.2f}%"
)

print(
    f"Peak CPU utilization    : "
    f"{peak_cpu:.2f}%"
)

print(
    f"Average memory usage    : "
    f"{average_memory:.2f}%"
)

print(
    f"Peak memory usage       : "
    f"{peak_memory:.2f}%"
)

print(
    f"HDFS storage size       : "
    f"{hdfs_size_mb:.4f} MB"
)

print(
    f"HDFS storage size       : "
    f"{hdfs_size_gb:.6f} GB"
)

print("=" * 60)

sys.exit(result.returncode)
