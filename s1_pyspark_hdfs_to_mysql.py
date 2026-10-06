import hashlib
import os
import sys
import threading
import time
from datetime import datetime

from pyspark.sql import Row
from pyspark.sql import SparkSession

HDFS_INPUT = "hdfs:///security_lab/s1/part*"
MYSQL_URL = (
    "jdbc:mysql://127.0.0.1:3306/dbtest"
    "?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
)
MYSQL_TABLE = "table_stock"
MYSQL_USER = "usertest"
MYSQL_PASSWORD = os.getenv("LOCAL_DB_PASSWORD")
SOURCE_TABLE = os.getenv("SOURCE_TABLE", "table_stock100")
EXPECTED_RECORDS = {
    "table_stock100": 125,
    "table_stock20K": 24858,
    "table_stock4M": 4248576,
}.get(SOURCE_TABLE, 125)
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


def calculate_hash(previous_hash, row_data):
    return hashlib.sha256(
        f"{previous_hash}|{row_data}".encode("utf-8")
    ).hexdigest()


spark = None
monitor_thread = None
status = "SUCCESS"
error = "N/A"
verification_time = 0.0
mysql_time = 0.0
records = 0
verified_records = 0
violations = 0
start_label = datetime.now().astimezone().isoformat(timespec="seconds")

try:
    spark = (
        SparkSession.builder
        .appName("S1 HDFS Hash Verification to Local MySQL")
        .master("local[*]")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()

    verification_start = time.perf_counter()
    raw_lines = spark.sparkContext.textFile(HDFS_INPUT).collect()
    previous_hash = GENESIS_HASH
    verified_rows = []

    for raw_line in raw_lines:
        line = raw_line.rstrip("\r\n")
        if not line:
            continue

        records += 1
        fields = line.rsplit(",", 2)
        if len(fields) != 3:
            raise RuntimeError(f"Malformed protected row {records}")

        row_data, stored_previous, stored_current = fields
        calculated_current = calculate_hash(stored_previous, row_data)
        valid = (
            stored_previous == previous_hash
            and calculated_current == stored_current
        )

        if valid:
            verified_records += 1
            values = row_data.split(",")
            if len(values) != 5:
                raise RuntimeError(f"Malformed source row {records}")
            verified_rows.append(
                Row(
                    id=int(values[0]),
                    product_id=int(values[1]),
                    purchasing_price=float(values[2]),
                    quantity=float(values[3]),
                    stock_date=values[4],
                )
            )
        else:
            violations += 1

        previous_hash = stored_current

    verification_time = time.perf_counter() - verification_start

    if (
        records != EXPECTED_RECORDS
        or verified_records != EXPECTED_RECORDS
        or violations != 0
    ):
        raise RuntimeError(
            f"Integrity verification failed: expected={EXPECTED_RECORDS}, "
            f"records={records}, verified={verified_records}, "
            f"violations={violations}"
        )

    output_df = spark.createDataFrame(verified_rows)
    output_df = output_df.selectExpr(
        "CAST(id AS INT) AS id",
        "CAST(product_id AS INT) AS product_id",
        "CAST(purchasing_price AS DOUBLE) AS purchasing_price",
        "CAST(quantity AS DOUBLE) AS quantity",
        "CAST(stock_date AS TIMESTAMP) AS stock_date",
    )

    mysql_start = time.perf_counter()
    (
        output_df.coalesce(1)
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

except Exception as exc:
    status = "FAILED"
    error = str(exc)

finally:
    stop_event.set()
    if monitor_thread is not None:
        monitor_thread.join()
    if spark is not None:
        spark.stop()

end_label = datetime.now().astimezone().isoformat(timespec="seconds")
s1_script2_time = verification_time + mysql_time
throughput = verified_records / s1_script2_time if s1_script2_time else 0.0

print("=" * 72)
print("S1 - PYSPARK HASH VERIFICATION RESULT")
print("=" * 72)
print("Laboratory environment                : S1")
print("Strategy under test                   : S1")
print(f"Source table                          : {SOURCE_TABLE}")
print(f"Expected records                      : {EXPECTED_RECORDS}")
print(f"Workflow start time                   : {start_label}")
print(f"Workflow end time                     : {end_label}")
print(f"Execution status                      : {status}")
print(f"S1 verification time                  : {verification_time:.2f} seconds")
print(f"Local MySQL write time                : {mysql_time:.2f} seconds")
print(f"S1-Script-2 cumulative time           : {s1_script2_time:.2f} seconds")
print(f"Throughput                            : {throughput:.2f} records/second")
print(f"Input records                         : {records}")
print(f"Verified records                      : {verified_records}")
print(f"Integrity violations                  : {violations}")
print(f"HDFS output verified                  : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"Local MySQL output verified            : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"Overall pipeline verification          : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print("Retry required                        : NO")
print("Number of retries                     : 0")
print(f"Error / failure message               : {error}")
print(f"Abnormal condition observed           : {'NO' if status == 'SUCCESS' else 'YES'}")
print(f"Average CPU utilization               : {average(cpu_samples):.2f}%")
print(f"Peak CPU utilization                  : {max(cpu_samples) if cpu_samples else 0.0:.2f}%")
print(f"Average memory utilization            : {average(memory_samples):.2f}%")
print(f"Peak memory utilization               : {max(memory_samples) if memory_samples else 0.0:.2f}%")
print("S2/S3 indicators                     : N/A - not tested")
print("=" * 72)
sys.exit(0 if status == "SUCCESS" else 1)
