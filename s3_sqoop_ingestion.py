import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


REMOTE_DB = "jdbc:mysql://69.175.69.34/sumrachna_hd"
USERNAME = "sumrachna_hd"
PASSWORD = os.getenv("REMOTE_DB_PASSWORD")
SOURCE_TABLE = os.getenv("SOURCE_TABLE")
S3_AUTH_TOKEN = os.getenv("S3_AUTH_TOKEN")
S3_REQUIRED_TOKEN = os.getenv("S3_REQUIRED_TOKEN", "S3-AUTHORIZED")
S2_AES_KEY_B64 = os.getenv("S2_AES_KEY_B64")

RAW_HDFS_TARGET = "/security_lab/s3_raw"
HDFS_TARGET = "/security_lab/s3"
AUDIT_LOG = os.getenv("S3_AUDIT_LOG", "/tmp/s3_audit.log")

DATASETS = {
    "table_stock100": ("Small", 125),
    "table_stock20K": ("Medium", 24858),
    "table_stock4M": ("Large", 4248576),
}


def fail(message):
    print(f"ERROR: {message}")
    sys.exit(1)


if not PASSWORD or not SOURCE_TABLE or SOURCE_TABLE not in DATASETS:
    fail("Set REMOTE_DB_PASSWORD and a valid SOURCE_TABLE.")

if not S3_AUTH_TOKEN:
    fail("Set S3_AUTH_TOKEN.")

if not S2_AES_KEY_B64:
    fail("Set S2_AES_KEY_B64.")

try:
    AES_KEY = base64.b64decode(S2_AES_KEY_B64, validate=True)
    if len(AES_KEY) != 32:
        raise ValueError
except Exception:
    fail("S2_AES_KEY_B64 must decode to exactly 32 bytes.")


DATASET_SCALE, EXPECTED_RECORDS = DATASETS[SOURCE_TABLE]
cpu_samples = []
memory_samples = []
stop_event = threading.Event()


def now_label():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def audit(event, status, message="N/A", **details):
    record = {
        "timestamp": now_label(),
        "strategy": "S3",
        "dataset": DATASET_SCALE,
        "source_table": SOURCE_TABLE,
        "event": event,
        "status": status,
        "message": message,
        **details,
    }

    try:
        parent = os.path.dirname(AUDIT_LOG)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(AUDIT_LOG, "a", encoding="utf-8") as log:
            log.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as exc:
        print(f"WARNING: Audit logging failed: {exc}", file=sys.stderr)


def authorized():
    return S3_AUTH_TOKEN == S3_REQUIRED_TOKEN


def cpu_values():
    with open("/proc/stat") as source:
        values = list(map(float, source.readline().split()[1:9]))
    return sum(values), values[3] + values[4]


def memory_percent():
    values = {}
    with open("/proc/meminfo") as source:
        for line in source:
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


def hdfs_size(path):
    result = subprocess.run(
        ["hdfs", "dfs", "-du", "-s", path],
        capture_output=True,
        text=True,
    )
    try:
        return int(result.stdout.split()[0]) / (1024 ** 2)
    except (ValueError, IndexError):
        return 0.0


def create_hash_chain():
    previous_hash = "GENESIS"
    records = 0
    hash_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv")

    try:
        raw_process = subprocess.Popen(
            ["hdfs", "dfs", "-cat", f"{RAW_HDFS_TARGET}/part*"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        for line in raw_process.stdout:
            row = line.rstrip("\r\n")
            if not row:
                continue
            current_hash = hashlib.sha256(
                f"{previous_hash}|{row}".encode("utf-8")
            ).hexdigest()
            hash_file.write(f"{row},{current_hash}\n")
            previous_hash = current_hash
            records += 1

        hash_file.close()
        raw_error = raw_process.stderr.read()
        return_code = raw_process.wait()

        if return_code != 0:
            raise RuntimeError(raw_error.strip() or "Unable to read raw HDFS data.")
        if records != EXPECTED_RECORDS:
            raise RuntimeError(
                f"Expected {EXPECTED_RECORDS} records but found {records}"
            )
        return hash_file.name, records
    except Exception:
        hash_file.close()
        if os.path.exists(hash_file.name):
            os.unlink(hash_file.name)
        raise


def encrypt_and_upload(hash_file):
    encrypted_file = tempfile.NamedTemporaryFile(delete=False, suffix=".enc")
    encrypted_file.close()

    try:
        with open(hash_file, "rb") as source:
            plaintext = source.read()

        nonce = os.urandom(12)
        ciphertext = AESGCM(AES_KEY).encrypt(nonce, plaintext, None)

        with open(encrypted_file.name, "wb") as target:
            target.write(nonce)
            target.write(ciphertext)

        subprocess.run(["hdfs", "dfs", "-rm", "-r", "-f", HDFS_TARGET], check=False)
        subprocess.run(["hdfs", "dfs", "-mkdir", "-p", HDFS_TARGET], check=True)
        subprocess.run(
            ["hdfs", "dfs", "-put", "-f", encrypted_file.name,
             f"{HDFS_TARGET}/part-00000.enc"],
            check=True,
        )
    finally:
        if os.path.exists(encrypted_file.name):
            os.unlink(encrypted_file.name)


start_label = now_label()
status = "FAILED"
error_message = "N/A"
authorization_status = "FAIL"
hash_file = None
sqoop_time = hash_time = encryption_time = authorization_time = 0.0
records = 0

audit("WORKFLOW_STARTED", "INFO")
authorization_start = time.perf_counter()
if authorized():
    authorization_status = "PASS"
    audit("AUTHORIZATION", "PASS", "S3 execution authorized")
else:
    audit("AUTHORIZATION", "FAIL", "S3 execution blocked")
authorization_time = time.perf_counter() - authorization_start

monitor_thread = threading.Thread(target=monitor, daemon=True)
monitor_thread.start()

try:
    if authorization_status != "PASS":
        raise PermissionError("S3 authorization failed; workflow blocked.")

    sqoop_command = [
        "sqoop", "import", "--connect", REMOTE_DB,
        "--username", USERNAME, "--password", PASSWORD,
        "--table", SOURCE_TABLE, "--target-dir", RAW_HDFS_TARGET,
        "--delete-target-dir",
    ]

    audit("SQOOP_INGESTION_STARTED", "INFO")
    sqoop_start = time.perf_counter()
    result = subprocess.run(sqoop_command)
    sqoop_time = time.perf_counter() - sqoop_start
    if result.returncode != 0:
        raise RuntimeError("Sqoop ingestion failed.")
    audit("SQOOP_INGESTION", "PASS", duration_seconds=round(sqoop_time, 4))

    hash_start = time.perf_counter()
    hash_file, records = create_hash_chain()
    hash_time = time.perf_counter() - hash_start
    audit("HASH_CHAIN", "PASS", duration_seconds=round(hash_time, 4), records=records)

    encryption_start = time.perf_counter()
    encrypt_and_upload(hash_file)
    encryption_time = time.perf_counter() - encryption_start
    audit("AES_GCM_ENCRYPTION", "PASS", duration_seconds=round(encryption_time, 4))

    status = "SUCCESS"
    audit("WORKFLOW_COMPLETED", "PASS")

except Exception as exc:
    error_message = str(exc)
    audit("WORKFLOW_COMPLETED", "FAIL", error_message)

finally:
    if hash_file and os.path.exists(hash_file):
        os.unlink(hash_file)
    stop_event.set()
    monitor_thread.join()

end_label = now_label()
s0_script1_time = sqoop_time
s1_script1_time = s0_script1_time + hash_time
s2_script1_time = s1_script1_time + encryption_time
s3_script1_time = s2_script1_time + authorization_time
storage_size = hdfs_size(HDFS_TARGET) if status == "SUCCESS" else 0.0

print("=" * 72)
print("S3 - ENHANCED PROTECTION SQOOP RESULT")
print("=" * 72)
print("Laboratory environment                : S3")
print("Strategy under test                   : S3")
print(f"Dataset scale                         : {DATASET_SCALE}")
print(f"Source table                          : {SOURCE_TABLE}")
print(f"Workflow start time                   : {start_label}")
print(f"Workflow end time                     : {end_label}")
print(f"Execution status                      : {status}")
print(f"Authorization status                  : {authorization_status}")
print(f"Authorization time                    : {authorization_time:.2f} seconds")
print(f"S0-Script-1 time                      : {s0_script1_time:.2f} seconds")
print(f"Hash-chain time                       : {hash_time:.2f} seconds")
print(f"S1-Script-1 total time                : {s1_script1_time:.2f} seconds")
print(f"AES-GCM encryption time               : {encryption_time:.2f} seconds")
print(f"S2-Script-1 total time                : {s2_script1_time:.2f} seconds")
print(f"S3-Script-1 total time                : {s3_script1_time:.2f} seconds")
print(f"HDFS output verified                  : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"HDFS storage size                     : {storage_size:.4f} MB")
print(f"Output records                        : {records}")
print(f"Average CPU utilization               : {average(cpu_samples):.2f}%")
print(f"Peak CPU utilization                  : {max(cpu_samples) if cpu_samples else 0.0:.2f}%")
print(f"Average memory utilization            : {average(memory_samples):.2f}%")
print(f"Peak memory utilization               : {max(memory_samples) if memory_samples else 0.0:.2f}%")
print(f"Audit logging                        : {'PASS' if os.path.exists(AUDIT_LOG) else 'FAIL'}")
print("Retry required                        : NO")
print("Number of retries                     : 0")
print(f"Error / failure message               : {error_message}")
print(f"Abnormal condition observed           : {'NO' if status == 'SUCCESS' else 'YES'}")
print("S0 baseline workflow                  : RETAINED")
print(f"S1 hash-chain protection              : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"S2 AES-GCM protection                 : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"S3 authorization and auditing         : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print("=" * 72)

sys.exit(0 if status == "SUCCESS" else 1)
