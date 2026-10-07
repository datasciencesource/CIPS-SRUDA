"""S3 Script-1: S0 + hash chain + AES-GCM + availability + audit.

Required: REMOTE_DB_PASSWORD, SOURCE_TABLE, S2_AES_KEY_B64.
No authorization token is required. Keep the same AES key for Script-2.
As in S2, a run replaces /security_lab/s3_raw and the final encrypted file.
Hash time includes reading raw HDFS data; encryption time includes upload.
Audit writes are timed separately, outside all processing-stage timers.
S2's ingestion, hashing, encryption/upload order is retained.
HDFS storage is reported in decimal MB (bytes / 1,000,000).
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

REMOTE_DB = "jdbc:mysql://69.175.69.34/sumrachna_hd"
USERNAME = "sumrachna_hd"
RAW_HDFS_TARGET = "/security_lab/s3_raw"
HDFS_TARGET = "/security_lab/s3"
HDFS_FILE = HDFS_TARGET + "/part-00000.enc"
DATASETS = {
    "table_stock100": ("Small", 125),
    "table_stock20K": ("Medium", 24858),
    "table_stock4M": ("Large", 4248576),
}


def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def cpu_values():
    with open("/proc/stat") as f:
        values = list(map(int, f.readline().split()[1:9]))
    return sum(values), values[3] + values[4]


def memory_percent():
    with open("/proc/meminfo") as f:
        values = {line.split(":")[0]: int(line.split()[1]) for line in f}
    return (1 - values["MemAvailable"] / values["MemTotal"]) * 100


class Monitor:
    def __init__(self):
        self.cpu, self.memory = [], []
        self.error = None
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            old_total, old_idle = cpu_values()
            while not self.stop.wait(0.5):
                total, idle = cpu_values()
                if total > old_total:
                    self.cpu.append((1 - (idle - old_idle) / (total - old_total)) * 100)
                self.memory.append(memory_percent())
                old_total, old_idle = total, idle
        except Exception as exc:
            self.error = str(exc)


def run_command(args, **kwargs):
    # Do not include command arguments in exceptions (credential hygiene).
    result = subprocess.run(args, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed with exit code {result.returncode}; see terminal output.")
    return result


def digest_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_hash_chain(path, expected):
    previous_hash, count = "GENESIS", 0
    # stderr is inherited: a full stderr pipe cannot deadlock the reader.
    with open(path, "w", encoding="utf-8", newline="\n") as target:
        process = subprocess.Popen(
            ["hdfs", "dfs", "-cat", RAW_HDFS_TARGET + "/part*"],
            stdout=subprocess.PIPE, text=True, encoding="utf-8",
        )
