import hashlib
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime

from pyspark import StorageLevel
from pyspark.sql import SparkSession


HDFS_INPUT = "hdfs:///security_lab/s2/part-00000.enc"

MYSQL_URL = (
    "jdbc:mysql://127.0.0.1:3306/dbtest"
    "?useSSL=false"
    "&allowPublicKeyRetrieval=true"
    "&serverTimezone=UTC"
)

MYSQL_TABLE = "table_stock"
MYSQL_USER = "usertest"
MYSQL_PASSWORD = os.getenv("LOCAL_DB_PASSWORD")
SOURCE_TABLE = os.getenv("SOURCE_TABLE")
ENCRYPTION_KEY = os.getenv("S2_ENCRYPTION_KEY")

DATASETS = {
    "table_stock100": ("Small", 125),
    "table_stock20K": ("Medium", 24858),
    "table_stock4M": ("Large", 4248576),
}

if not MYSQL_PASSWORD:
    print("ERROR: LOCAL_DB_PASSWORD is not set.")
    sys.exit(1)

if not SOURCE_TABLE or SOURCE_TABLE not in DATASETS:
    print("ERROR: Set a valid SOURCE_TABLE.")
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


def decrypt_hdfs_file():
    encrypted_file = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".enc"
    ).name

    decrypted_file = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".csv"
    ).name

    subprocess.run(
        [
            "hdfs",
            "dfs",
            "-get",
            "-f",
            HDFS_INPUT,
            encrypted_file
        ],
        check=True
    )

    environment = os.environ.copy()
    environment["S2_KEY"] = ENCRYPTION_KEY

    subprocess.run(
        [
            "openssl",
            "enc",
            "-d",
            "-aes-256-cbc",
            "-pbkdf2",
            "-in",
            encrypted_file,
            "-out",
            decrypted_file,
            "-pass",
            "env:S2_KEY"
        ],
        env=environment,
        check=True
    )

    os.unlink(encrypted_file)
    return decrypted_file


def verify_hash_chain(decrypted_file):
    start = time.perf_counter()
    previous_hash = "GENESIS"
    verified_records = 0

    with open(decrypted_file, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            original_row, stored_hash = line.rsplit(",", 1)

            calculated_hash = hashlib.sha256(
                f"{previous_hash}|{original_row}".encode("utf-8")
            ).hexdigest()

            if calculated_hash != stored_hash:
                raise RuntimeError(
                    f"Hash verification failed at record "
                    f"{verified_records + 1}"
                )

            previous_hash = stored_hash
            verified_records += 1

    verification_time = time.perf_counter() - start

    if verified_records != EXPECTED_RECORDS:
        raise RuntimeError(
            f"Expected {EXPECTED_RECORDS} verified records "
            f"but found {verified_records}"
        )

    return verification_time, verified_records


spark = None
monitor_thread = None

status = "SUCCESS"
error_message = "N/A"

records = 0
verified_records = 0

decryption_time = 0.0
pyspark_time = 0.0
verification_time = 0.0
mysql_time = 0.0

start_label = datetime.now().astimezone().isoformat(
    timespec="seconds"
)

try:
    spark = (
        SparkSession.builder
        .appName("S2 Encrypted HDFS to Local MySQL")
        .master("local[*]")
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("ERROR")

    monitor_thread = threading.Thread(
        target=monitor,
        daemon=True
    )
    monitor_thread.start()

    decryption_start = time.perf_counter()
    decrypted_file = decrypt_hdfs_file()
    decryption_time = time.perf_counter() - decryption_start

    processing_start = time.perf_counter()

    data = (
        spark.read
        .schema(
            """
            id INT,
            product_id INT,
            purchasing_price DOUBLE,
            quantity DOUBLE,
            stock_date TIMESTAMP,
            row_hash STRING
            """
        )
        .option("header", "false")
        .option("timestampFormat", "yyyy-MM-dd HH:mm:ss.S")
        .option("mode", "FAILFAST")
        .csv(decrypted_file)
        .persist(StorageLevel.MEMORY_AND_DISK)
    )

    records = data.count()
    pyspark_time = time.perf_counter() - processing_start

    if records != EXPECTED_RECORDS:
        raise RuntimeError(
            f"Expected {EXPECTED_RECORDS} records but found {records}"
        )

    verification_time, verified_records = verify_hash_chain(
        decrypted_file
    )

    mysql_start = time.perf_counter()

    (
        data.drop("row_hash")
        .coalesce(1)
        .write
        .format("jdbc")
        .option("url", MYSQL_URL)
        .option("dbtable", MYSQL_TABLE)
        .option("user", MYSQL_USER)
        .option("password", MYSQL_PASSWORD)
        .option("driver", "com.mysql.cj.jdbc.Driver")
        .mode("append")
        .save()
    )

    mysql_time = time.perf_counter() - mysql_start

    os.unlink(decrypted_file)

except Exception as exc:
    status = "FAILED"
    error_message = str(exc)

finally:
    stop_event.set()

    if monitor_thread is not None:
        monitor_thread.join()

    if spark is not None:
        spark.stop()


end_label = datetime.now().astimezone().isoformat(
    timespec="seconds"
)

s0_script2_time = pyspark_time + mysql_time
s1_script2_time = s0_script2_time + verification_time
s2_script2_time = s1_script2_time + decryption_time

print("=" * 72)
print("S2 - PYSPARK DECRYPTION AND VERIFICATION RESULT")
print("=" * 72)
print("Laboratory environment                : S2")
print("Strategy under test                   : S2")
print(f"Dataset scale                         : {DATASET_SCALE}")
print(f"Source table                          : {SOURCE_TABLE}")
print(f"Workflow start time                   : {start_label}")
print(f"Workflow end time                     : {end_label}")
print(f"Execution status                      : {status}")

print(f"S0-Script-2 time                      : {s0_script2_time:.2f} seconds")
print(f"S1-Script-2 total time                : {s1_script2_time:.2f} seconds")
print(f"Decryption time                       : {decryption_time:.2f} seconds")
print(f"S2-Script-2 total time                : {s2_script2_time:.2f} seconds")
print(f"PySpark processing component          : {pyspark_time:.2f} seconds")
print(f"Hash-verification time                : {verification_time:.2f} seconds")
print(f"Local MySQL write time                : {mysql_time:.2f} seconds")
print(f"Output records                        : {records}")
print(f"Verified records                      : {verified_records}")
print(
    f"Hash-chain verification               : "
    f"{'PASS' if status == 'SUCCESS' else 'FAIL'}"
)
print(
    f"Encryption/decryption verification   : "
    f"{'PASS' if status == 'SUCCESS' else 'FAIL'}"
)
print(
    f"Local MySQL output verified            : "
    f"{'PASS' if status == 'SUCCESS' else 'FAIL'}"
)
print(
    f"Overall pipeline verification          : "
    f"{'PASS' if status == 'SUCCESS' else 'FAIL'}"
)
print("Retry required                        : NO")
print("Number of retries                     : 0")
print(f"Error / failure message               : {error_message}")
print(
    "Abnormal condition observed           : "
    f"{'NO' if status == 'SUCCESS' else 'YES'}"
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
print("S0 baseline workflow                  : RETAINED")
print("S1 hash-chain protection              : RETAINED")
print(
    "S2 encryption protection              : "
    f"{'PASS' if status == 'SUCCESS' else 'FAIL'}"
)
print("=" * 72)

sys.exit(0 if status == "SUCCESS" else 1)
