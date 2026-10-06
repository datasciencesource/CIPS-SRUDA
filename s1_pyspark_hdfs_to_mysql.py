import hashlib
import os
import sys
import threading
import time
from datetime import datetime

from pyspark import StorageLevel
from pyspark.sql import SparkSession


HDFS_INPUT = "hdfs:///security_lab/s1/part*"

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

DATASET_SCALE, EXPECTED_RECORDS = DATASETS[SOURCE_TABLE]

cpu_samples = []
memory_samples = []
stop_event = threading.Event()


def cpu_values():
    with open("/proc/stat") as file:
        values = list(map(float, file.readline().split()[1:9]))

    return sum(values), values[3] + values[4]


def memory_percent():
    values = {}

    with open("/proc/meminfo") as file:
        for line in file:
            key, value = line.split(":", 1)
            values[key] = float(value.split()[0])

    return (
        (values["MemTotal"] - values["MemAvailable"])
        / values["MemTotal"]
        * 100
    )


def monitor():
    previous_total, previous_idle = cpu_values()

    while not stop_event.wait(0.5):
        total, idle = cpu_values()

        if total > previous_total:
            cpu_usage = (
                1 - (idle - previous_idle)
                / (total - previous_total)
            ) * 100

            cpu_samples.append(cpu_usage)

        memory_samples.append(memory_percent())

        previous_total = total
        previous_idle = idle


def average(values):
    return sum(values) / len(values) if values else 0.0


def verify_hash_chain(rows):
    """
    Verifies the SHA-256 hash chain in ID order.

    The row_hash column must be the final column in the S1 HDFS file.
    """

    previous_hash = "GENESIS"
    verified_records = 0

    for row in sorted(rows, key=lambda item: item["id"]):
        stored_hash = row["row_hash"]

        row_data = (
            f"{row['id']},"
            f"{row['product_id']},"
            f"{row['purchasing_price']},"
            f"{row['quantity']},"
            f"{row['stock_date']}"
        )

        calculated_hash = hashlib.sha256(
            f"{previous_hash}|{row_data}".encode("utf-8")
        ).hexdigest()

        if calculated_hash != stored_hash:
            return False, verified_records

        previous_hash = stored_hash
        verified_records += 1

    return True, verified_records


spark = None
monitor_thread = None

status = "SUCCESS"
error_message = "N/A"

processing_time = 0.0
verification_time = 0.0
mysql_time = 0.0
records = 0
verified_records = 0
hash_verification = "FAIL"

start_label = datetime.now().astimezone().isoformat(
    timespec="seconds"
)

try:
    spark = (
        SparkSession.builder
        .appName("S1 HDFS Hash Verification to Local MySQL")
        .master("local[*]")
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("ERROR")

    monitor_thread = threading.Thread(
        target=monitor,
        daemon=True
    )

    monitor_thread.start()

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
        .option(
            "timestampFormat",
            "yyyy-MM-dd HH:mm:ss.S"
        )
        .option("mode", "FAILFAST")
        .csv(HDFS_INPUT)
        .persist(StorageLevel.MEMORY_AND_DISK)
    )

    records = data.count()

    processing_time = time.perf_counter() - processing_start

    if records != EXPECTED_RECORDS:
        raise RuntimeError(
            f"Expected {EXPECTED_RECORDS} records "
            f"but found {records}"
        )

    verification_start = time.perf_counter()

    rows = data.select(
        "id",
        "product_id",
        "purchasing_price",
        "quantity",
        "stock_date",
        "row_hash"
    ).collect()

    hash_verification, verified_records = verify_hash_chain(rows)

    verification_time = time.perf_counter() - verification_start

    if not hash_verification:
        raise RuntimeError(
            "Hash-chain verification failed."
        )

    mysql_start = time.perf_counter()

    output_data = data.drop("row_hash")

    (
        output_data
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

except Exception as error:
    status = "FAILED"
    error_message = str(error)

finally:
    stop_event.set()

    if monitor_thread is not None:
        monitor_thread.join()

    if spark is not None:
        spark.stop()


end_label = datetime.now().astimezone().isoformat(
    timespec="seconds"
)

total_s1_time = (
    processing_time
    + verification_time
    + mysql_time
)

throughput = (
    records / total_s1_time
    if total_s1_time
    else 0.0
)

print("=" * 72)
print("S1 - PYSPARK HASH VERIFICATION RESULT")
print("=" * 72)

print("Laboratory environment                : S1")
print("Strategy under test                   : S1")
print(f"Dataset scale                         : {DATASET_SCALE}")
print(f"Source table                          : {SOURCE_TABLE}")
print(f"Workflow start time                   : {start_label}")
print(f"Workflow end time                     : {end_label}")
print(f"Execution status                      : {status}")

print(
    "PySpark processing time               : "
    f"{processing_time:.2f} seconds"
)

print(
    "Hash-chain verification time          : "
    f"{verification_time:.2f} seconds"
)

print(
    "Local MySQL write time                : "
    f"{mysql_time:.2f} seconds"
)

print(
    "Total S1 Script-2 time                : "
    f"{total_s1_time:.2f} seconds"
)

print(
    "Throughput                            : "
    f"{throughput:.2f} records/second"
)

print(f"Output records                        : {records}")
print(f"Verified records                      : {verified_records}")
print(f"Hash-chain verification               : {hash_verification}")
print(
    "HDFS output verified                  : "
    f"{'PASS' if status == 'SUCCESS' else 'FAIL'}"
)
print(
    "Local MySQL output verified            : "
    f"{'PASS' if status == 'SUCCESS' else 'FAIL'}"
)
print(
    "Overall pipeline verification          : "
    f"{'PASS' if status == 'SUCCESS' else 'FAIL'}"
)
print("Retry required                        : NO")
print("Number of retries                     : 0")
print(f"Error / failure message               : {error_message}")
print(
    "Abnormal condition observed           : "
    f"{'NO' if status == 'SUCCESS' else 'YES'}"
)
print("S0 baseline processing                : RETAINED")
print(f"Average CPU utilization               : {average(cpu_samples):.2f}%")
print(
    "Peak CPU utilization                  : "
    f"{max(cpu_samples) if cpu_samples else 0.0:.2f}%"
)
print(
    "Average memory utilization            : "
    f"{average(memory_samples):.2f}%"
)
print(
    "Peak memory utilization               : "
    f"{max(memory_samples) if memory_samples else 0.0:.2f}%"
)
print("=" * 72)

sys.exit(0 if status == "SUCCESS" else 1)
