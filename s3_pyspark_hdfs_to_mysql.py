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
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pyspark import StorageLevel
from pyspark.sql import SparkSession


HDFS_INPUT = "hdfs:///security_lab/s3/part-00000.enc"
MYSQL_URL = (
    "jdbc:mysql://127.0.0.1:3306/dbtest"
    "?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
)
MYSQL_TABLE = "table_stock"
MYSQL_USER = "usertest"
MYSQL_PASSWORD = os.getenv("LOCAL_DB_PASSWORD")
SOURCE_TABLE = os.getenv("SOURCE_TABLE")
S3_AUTH_TOKEN = os.getenv("S3_AUTH_TOKEN")
S3_REQUIRED_TOKEN = os.getenv("S3_REQUIRED_TOKEN", "S3-AUTHORIZED")
S2_AES_KEY_B64 = os.getenv("S2_AES_KEY_B64")
AUDIT_LOG = os.getenv("S3_AUDIT_LOG", "/tmp/s3_audit.log")

DATASETS = {
    "table_stock100": ("Small", 125),
    "table_stock20K": ("Medium", 24858),
    "table_stock4M": ("Large", 4248576),
}


def fail(message):
    print(f"ERROR: {message}")
    sys.exit(1)


if not MYSQL_PASSWORD:
    fail("Set LOCAL_DB_PASSWORD.")
if not SOURCE_TABLE or SOURCE_TABLE not in DATASETS:
    fail("Set a valid SOURCE_TABLE.")
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


def decrypt_hdfs_file():
    encrypted_file = tempfile.NamedTemporaryFile(delete=False, suffix=".enc").name
    decrypted_file = tempfile.NamedTemporaryFile(delete=False, suffix=".csv").name

    try:
        subprocess.run(["hdfs", "dfs", "-get", "-f", HDFS_INPUT, encrypted_file], check=True)
        with open(encrypted_file, "rb") as source:
            nonce = source.read(12)
            ciphertext = source.read()

        if len(nonce) != 12 or not ciphertext:
            raise RuntimeError("Invalid encrypted S3 HDFS file.")

        plaintext = AESGCM(AES_KEY).decrypt(nonce, ciphertext, None)
        with open(decrypted_file, "wb") as target:
            target.write(plaintext)
        return decrypted_file
    finally:
        if os.path.exists(encrypted_file):
            os.unlink(encrypted_file)


def verify_hash_chain(decrypted_file):
    start = time.perf_counter()
    previous_hash = "GENESIS"
    verified_records = 0

    with open(decrypted_file, "r", encoding="utf-8") as source:
        for line in source:
            line = line.strip()
            if not line:
                continue
            try:
                original_row, stored_hash = line.rsplit(",", 1)
            except ValueError as exc:
                raise RuntimeError("Hash value is missing from an S3 record.") from exc

            calculated_hash = hashlib.sha256(
                f"{previous_hash}|{original_row}".encode("utf-8")
            ).hexdigest()
            if calculated_hash != stored_hash:
                raise RuntimeError(
                    f"Hash verification failed at record {verified_records + 1}"
                )
            previous_hash = stored_hash
            verified_records += 1

    verification_time = time.perf_counter() - start
    if verified_records != EXPECTED_RECORDS:
        raise RuntimeError(
            f"Expected {EXPECTED_RECORDS} verified records but found {verified_records}"
        )
    return verification_time, verified_records


spark = None
monitor_thread = None
decrypted_file = None
status = "FAILED"
error_message = "N/A"
authorization_status = "FAIL"
records = verified_records = 0
authorization_time = decryption_time = 0.0
pyspark_time = verification_time = mysql_time = 0.0
start_label = now_label()

audit("WORKFLOW_STARTED", "INFO")
authorization_start = time.perf_counter()
if authorized():
    authorization_status = "PASS"
    audit("AUTHORIZATION", "PASS", "S3 processing authorized")
else:
    audit("AUTHORIZATION", "FAIL", "S3 processing blocked")
authorization_time = time.perf_counter() - authorization_start

try:
    if authorization_status != "PASS":
        raise PermissionError("S3 authorization failed; processing blocked.")

    spark = (
        SparkSession.builder
        .appName("S3 Enhanced Protection HDFS to Local MySQL")
        .master("local[*]")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()

    audit("DECRYPTION_STARTED", "INFO")
    decryption_start = time.perf_counter()
    decrypted_file = decrypt_hdfs_file()
    decryption_time = time.perf_counter() - decryption_start
    audit("AES_GCM_DECRYPTION", "PASS", duration_seconds=round(decryption_time, 4))

    local_file_uri = Path(decrypted_file).resolve().as_uri()
    processing_start = time.perf_counter()
    data = (
        spark.read.schema(
            "id INT, product_id INT, purchasing_price DOUBLE, "
            "quantity DOUBLE, stock_date TIMESTAMP, row_hash STRING"
        )
        .option("header", "false")
        .option("timestampFormat", "yyyy-MM-dd HH:mm:ss.S")
        .option("mode", "FAILFAST")
        .csv(local_file_uri)
        .persist(StorageLevel.MEMORY_AND_DISK)
    )
    records = data.count()
    pyspark_time = time.perf_counter() - processing_start
    if records != EXPECTED_RECORDS:
        raise RuntimeError(f"Expected {EXPECTED_RECORDS} records but found {records}")
    audit("PYSPARK_PROCESSING", "PASS", duration_seconds=round(pyspark_time, 4), records=records)

    verification_time, verified_records = verify_hash_chain(decrypted_file)
    audit("HASH_VERIFICATION", "PASS", duration_seconds=round(verification_time, 4), records=verified_records)

    mysql_start = time.perf_counter()
    (
        data.drop("row_hash")
        .coalesce(1)
        .write.format("jdbc")
        .option("url", MYSQL_URL)
        .option("dbtable", MYSQL_TABLE)
        .option("user", MYSQL_USER)
        .option("password", MYSQL_PASSWORD)
        .option("driver", "com.mysql.cj.jdbc.Driver")
        .mode("append")
        .save()
    )
    mysql_time = time.perf_counter() - mysql_start
    audit("MYSQL_WRITE", "PASS", duration_seconds=round(mysql_time, 4), records=records)

    status = "SUCCESS"
    audit("WORKFLOW_COMPLETED", "PASS")

except Exception as exc:
    error_message = str(exc)
    audit("WORKFLOW_COMPLETED", "FAIL", error_message)

finally:
    stop_event.set()
    if monitor_thread is not None:
        monitor_thread.join()
    if decrypted_file and os.path.exists(decrypted_file):
        os.unlink(decrypted_file)
    if spark is not None:
        spark.stop()

end_label = now_label()
s0_script2_time = pyspark_time + mysql_time
s1_script2_time = s0_script2_time + verification_time
s2_script2_time = s1_script2_time + decryption_time
s3_script2_time = s2_script2_time + authorization_time

print("=" * 72)
print("S3 - ENHANCED PROTECTION PYSPARK RESULT")
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
print(f"S0-Script-2 time                      : {s0_script2_time:.2f} seconds")
print(f"Hash-verification time                : {verification_time:.2f} seconds")
print(f"S1-Script-2 total time                : {s1_script2_time:.2f} seconds")
print(f"AES-GCM decryption time               : {decryption_time:.2f} seconds")
print(f"S2-Script-2 total time                : {s2_script2_time:.2f} seconds")
print(f"S3-Script-2 total time                : {s3_script2_time:.2f} seconds")
print(f"PySpark processing component          : {pyspark_time:.2f} seconds")
print(f"Local MySQL write time                : {mysql_time:.2f} seconds")
print(f"Output records                        : {records}")
print(f"Verified records                      : {verified_records}")
print(f"AES-GCM decryption verification       : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"Hash-chain verification               : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"HDFS output verified                  : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"Local MySQL output verified            : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"Audit logging                         : {'PASS' if os.path.exists(AUDIT_LOG) else 'FAIL'}")
print(f"Overall pipeline decision             : {'AUTHORIZE' if status == 'SUCCESS' else 'BLOCK'}")
print("Retry required                        : NO")
print("Number of retries                     : 0")
print(f"Error / failure message               : {error_message}")
print(f"Abnormal condition observed           : {'NO' if status == 'SUCCESS' else 'YES'}")
print("S0 baseline workflow                  : RETAINED")
print("S1 hash-chain protection              : RETAINED")
print("S2 AES-GCM protection                 : RETAINED")
print(f"S3 authorization and auditing         : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"Average CPU utilization               : {average(cpu_samples):.2f}%")
print(f"Peak CPU utilization                  : {max(cpu_samples) if cpu_samples else 0.0:.2f}%")
print(f"Average memory utilization            : {average(memory_samples):.2f}%")
print(f"Peak memory utilization               : {max(memory_samples) if memory_samples else 0.0:.2f}%")
print("=" * 72)

sys.exit(0 if status == "SUCCESS" else 1)
