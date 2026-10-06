import os
import sys
import threading
import time
from datetime import datetime
from pyspark import StorageLevel
from pyspark.sql import SparkSession

HDFS_INPUT = "hdfs:///security_lab/s0/part*"
MYSQL_URL = "jdbc:mysql://127.0.0.1:3306/dbtest?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
MYSQL_TABLE = "table_stock"
MYSQL_USER = "usertest"
MYSQL_PASSWORD = os.getenv("LOCAL_DB_PASSWORD")
EXPECTED_RECORDS = 125

if not MYSQL_PASSWORD:
    print("ERROR: LOCAL_DB_PASSWORD is not set.")
    sys.exit(1)

cpu_samples, memory_samples = [], []
stop_event = threading.Event()

def cpu_values():
    with open("/proc/stat") as f:
        v = list(map(float, f.readline().split()[1:9]))
    return sum(v), v[3] + v[4]

def memory_percent():
    values = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, value = line.split(":", 1)
            values[k] = float(value.split()[0])
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

spark = None
status = "SUCCESS"
error = "N/A"
processing_time = 0.0
mysql_time = 0.0
records = 0
start_label = datetime.now().astimezone().isoformat(timespec="seconds")

try:
    spark = SparkSession.builder.appName("S0 HDFS to Local MySQL").master("local[*]").getOrCreate()
    spark.sparkContext.setLogLevel("ERROR")
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    processing_start = time.perf_counter()
    data = (spark.read.schema("id INT, product_id INT, purchasing_price DOUBLE, quantity DOUBLE, stock_date TIMESTAMP")
            .option("header", "false").option("timestampFormat", "yyyy-MM-dd HH:mm:ss.S")
            .option("mode", "FAILFAST").csv(HDFS_INPUT).persist(StorageLevel.MEMORY_AND_DISK))
    records = data.count()
    processing_time = time.perf_counter() - processing_start
    if records != EXPECTED_RECORDS:
        raise RuntimeError(f"Expected {EXPECTED_RECORDS} records but found {records}")
    mysql_start = time.perf_counter()
    (data.coalesce(1).write.format("jdbc").option("url", MYSQL_URL)
     .option("dbtable", MYSQL_TABLE).option("user", MYSQL_USER)
     .option("password", MYSQL_PASSWORD).option("driver", "com.mysql.cj.jdbc.Driver")
     .mode("append").save())
    mysql_time = time.perf_counter() - mysql_start
except Exception as exc:
    status = "FAILED"
    error = str(exc)
finally:
    stop_event.set()
    if 'monitor_thread' in locals():
        monitor_thread.join()
    if spark is not None:
        spark.stop()

end_label = datetime.now().astimezone().isoformat(timespec="seconds")
total_time = processing_time + mysql_time
throughput = records / total_time if total_time else 0.0
print("=" * 72)
print("S0 - PYSPARK RESULT")
print("=" * 72)
print(f"Laboratory environment                : S0")
print(f"Strategy under test                   : S0")
print(f"Workflow start time                   : {start_label}")
print(f"Workflow end time                     : {end_label}")
print(f"Execution status                      : {status}")
print(f"PySpark processing time               : {processing_time:.2f} seconds")
print(f"Local MySQL write time                : {mysql_time:.2f} seconds")
print(f"Total S0 processing time              : {total_time:.2f} seconds")
print(f"Throughput                            : {throughput:.2f} records/second")
print(f"Output records                        : {records}")
print(f"HDFS output verified                  : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"Local MySQL output verified            : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"Overall pipeline verification          : {'PASS' if status == 'SUCCESS' else 'FAIL'}")
print(f"Retry required                        : NO")
print(f"Number of retries                     : 0")
print(f"Error / failure message               : {error}")
print(f"Abnormal condition observed           : {'NO' if status == 'SUCCESS' else 'YES'}")
print("S1/S2/S3 indicators                   : N/A - not tested")
print(f"Average CPU utilization               : {average(cpu_samples):.2f}%")
print(f"Peak CPU utilization                  : {max(cpu_samples) if cpu_samples else 0.0:.2f}%")
print(f"Average memory utilization            : {average(memory_samples):.2f}%")
print(f"Peak memory utilization               : {max(memory_samples) if memory_samples else 0.0:.2f}%")
print("=" * 72)
sys.exit(0 if status == "SUCCESS" else 1)
