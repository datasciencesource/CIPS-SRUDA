import hashlib
import os
import sys
import threading
import time
from datetime import datetime

from pyspark.sql import SparkSession

HDFS_INPUT = "hdfs:///security_lab/s1/part*"
MYSQL_URL = (
    "jdbc:mysql://127.0.0.1:3306/dbtest"
    "?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
)
MYSQL_TABLE = "table_stock"
MYSQL_USER = "usertest"
MYSQL_PASSWORD = os.getenv("LOCAL_DB_PASSWORD")
EXPECTED_RECORDS = {
    "table_stock100": 125,
    "table_stock20K": 24858,
    "table_stock4M": 4248576,
}
SOURCE_TABLE = os.getenv("SOURCE_TABLE", "table_stock100")
EXPECTED = EXPECTED_RECORDS.get(SOURCE_TABLE, 125)
GENESIS_HASH = "GENESIS"

if not MYSQL_PASSWORD:
    print("ERROR: LOCAL_DB_PASSWORD is not set.")
    sys.exit(1)

cpu_samples, memory_samples = [], []
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
    return (values["MemTotal"] - values["MemAvailable"]) / values["MemTotal"] * 100


def monitor():
    old_total, old_idle = cpu_values()
    while not stop_event.wait(0.5):
        total, idle = cpu_values()
        if total > old_total:
            cpu_samples.append((1 - (idle - old_idle) / (total - old_total)) * 100)
        memory_samples.append(memory_percent())
        old_total, old_idle = total, idle


def average(values):
    return sum(values) / len(values) if values else 0.0


def chain_hash(previous_hash, row):
    return hashlib.sha256(f"{previous_hash}|{row}".encode()).hexdigest()


spark = None
monitor_thread = None
status = "SUCCESS"
error = "N/A"
processing_time = 0.0
mysql_time = 0.0
records = 0
verified_records = 0
violations = 0
start_label = datetime.now().astimezone().isoformat(timespec="seconds")

try:
    spark = SparkSession.builder.appName("S1 HDFS Verification to Local MySQL").master("local[*]").getOrCreate()
    spark.sparkContext.setLogLevel("ERROR")
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()

    processing_start = time.perf_counter()
    raw = spark.sparkContext.textFile(HDFS_INPUT)
    rows = []
    previous_hash = GENESIS_HASH

    for line in raw.collect():
        line = line.rstrip("\r\n")
        if not line:
            continue
        records += 1
        try:
            row_data, stored_previous, stored_current = line.rsplit(",", 2)
