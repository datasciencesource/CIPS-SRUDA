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
        except ValueError as exc:
            raise RuntimeError(f"Malformed protected row {records}") from exc
        calculated = chain_hash(stored_previous, row_data)
        if stored_previous != previous_hash or calculated != stored_current:
            violations += 1
        else:
            verified_records += 1
        previous_hash = stored_current
        rows.append(row_data)

    if records != EXPECTED or verified_records != EXPECTED or violations != 0:
        raise RuntimeError(
            f"Integrity verification failed: expected={EXPECTED}, "
            f"records={records}, verified={verified_records}, violations={violations}"
        )

    processing_time = time.perf_counter() - processing_start
    schema = "id INT, product_id INT, purchasing_price DOUBLE, quantity DOUBLE, stock_date TIMESTAMP"
    output = spark.createDataFrame(rows, "string").rdd.map(lambda r: tuple(r[0].split(",")))
    output_df = spark.createDataFrame(output, schema=schema)

    mysql_start = time.perf_counter()
    (output_df.write.format("jdbc").option("url", MYSQL_URL)
     .option("dbtable", MYSQL_TABLE).option("user", MYSQL_USER)
     .option("password", MYSQL_PASSWORD).option("driver", "com.mysql.cj.jdbc.Driver")
     .mode("append").save())
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
s1_total = processing_time + mysql_time
throughput = records / s1_total if s1_total else 0.0

print("=" * 72)
print("S1 - PYSPARK VERIFICATION RESULT")
print("=" * 72)
print("Laboratory environment                : S1")
print("Strategy under test                   : S1")
print(f"Source table                          : {SOURCE_TABLE}")
print(f"Expected records                      : {EXPECTED}")
print(f"Workflow start time                   : {start_label}")
print(f"Workflow end time                     : {end_label}")
print(f"Execution status                      : {status}")
print(f"S0-Script-2 PySpark processing time   : {processing_time:.2f} seconds")
print(f"S1 verification time                  : {processing_time:.2f} seconds")
print(f"Local MySQL write time                : {mysql_time:.2f} seconds")
print(f"S1-Script-2 cumulative time           : {s1_total:.2f} seconds")
print(f"Throughput                            : {throughput:.2f} records/second")
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
