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
