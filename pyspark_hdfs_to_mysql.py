import os
import sys
import threading
import time

from pyspark.sql import SparkSession
from pyspark import StorageLevel

# =====================================
# S0 - PySpark Configuration
# =====================================

HDFS_INPUT = "hdfs:///security_lab/s0/part*"

MYSQL_URL = (
    "jdbc:mysql://127.0.0.1:3306/dbtest"
    "?useSSL=false"
    "&allowPublicKeyRetrieval=true"
    "&serverTimezone=UTC"
)

MYSQL_TABLE = "table_stock"
MYSQL_USER = "usertest"
MYSQL_PASSWORD = os.getenv("LOCAL_DB_PASSWORD")

# =====================================
# Check Credential
# =====================================

if not MYSQL_PASSWORD:
    print("ERROR: LOCAL_DB_PASSWORD is not set.")
    print("Run:")
    print("export LOCAL_DB_PASSWORD='your_password'")
    sys.exit(1)

# =====================================
# Resource Monitoring
# =====================================

cpu_samples = []
memory_samples = []
stop_monitoring = threading.Event()


def get_cpu_values():
    with open("/proc/stat", "r") as f:
        values = list(map(float, f.readline().split()[1:9]))

    user, nice, system, idle, iowait, irq, softirq, steal = values

    idle_total = idle + iowait
    active_total = user + nice + system + irq + softirq + steal
    total = idle_total + active_total

    return total, idle_total


def get_memory_percent():
    meminfo = {}

    with open("/proc/meminfo", "r") as f:
        for line in f:
            key, value = line.split(":", 1)
            meminfo[key] = float(value.strip().split()[0])

    total = meminfo["MemTotal"]
    available = meminfo["MemAvailable"]

    return ((total - available) / total) * 100


def monitor_resources():
    previous_total, previous_idle = get_cpu_values()

    while not stop_monitoring.wait(0.5):

        current_total, current_idle = get_cpu_values()

        total_delta = current_total - previous_total
        idle_delta = current_idle - previous_idle

        if total_delta > 0:
            cpu_percent = (
                (total_delta - idle_delta) / total_delta
            ) * 100

            cpu_samples.append(cpu_percent)

        memory_samples.append(get_memory_percent())

        previous_total = current_total
        previous_idle = current_idle


monitor_thread = threading.Thread(
    target=monitor_resources,
    daemon=True
)

# =====================================
# Start Monitoring
# =====================================

monitor_thread.start()

spark = None
data = None

pyspark_processing_time = 0.0
mysql_write_time = 0.0
record_count = 0

status = "SUCCESS"
error_message = ""

try:

    print("=" * 60)
    print("S0 - PYSPARK PROCESSING")
    print("=" * 60)

    # =====================================
    # Start Spark
    # =====================================

    spark = (
        SparkSession.builder
        .appName("S0 HDFS to Local MySQL")
        .master("local[*]")
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("ERROR")

    # =====================================
    # Schema
    # =====================================

    schema = """
        id INT,
        product_id INT,
        purchasing_price DOUBLE,
        quantity DOUBLE,
        stock_date TIMESTAMP
    """

    # =====================================
    # PySpark Processing
    # =====================================

    processing_start = time.time()

    data = (
        spark.read
        .schema(schema)
        .option("header", "false")
        .option(
            "timestampFormat",
            "yyyy-MM-dd HH:mm:ss.S"
        )
        .option("mode", "FAILFAST")
        .csv(HDFS_INPUT)
    )

    data.persist(StorageLevel.MEMORY_AND_DISK)

    # Force Spark execution
    record_count = data.count()

    processing_end = time.time()

    pyspark_processing_time = (
        processing_end - processing_start
    )

    data.show(5, truncate=False)

    # =====================================
    # Local MySQL Write
    # =====================================

    mysql_start = time.time()

    (
        data.coalesce(1)
        .write
        .format("jdbc")
        .option("url", MYSQL_URL)
        .option("dbtable", MYSQL_TABLE)
        .option("user", MYSQL_USER)
        .option("password", MYSQL_PASSWORD)
        .option(
            "driver",
            "com.mysql.cj.jdbc.Driver"
        )
        .mode("append")
        .save()
    )

    mysql_end = time.time()

    mysql_write_time = (
        mysql_end - mysql_start
    )

except Exception as error:

    status = "FAILED"
    error_message = str(error)

finally:

    if data is not None:
        data.unpersist()

    if spark is not None:
        spark.stop()

    stop_monitoring.set()
    monitor_thread.join()

# =====================================
# Resource Results
# =====================================

average_cpu = (
    sum(cpu_samples) / len(cpu_samples)
    if cpu_samples else 0.0
)

peak_cpu = (
    max(cpu_samples)
    if cpu_samples else 0.0
)

average_memory = (
    sum(memory_samples) / len(memory_samples)
    if memory_samples else 0.0
)

peak_memory = (
    max(memory_samples)
    if memory_samples else 0.0
)

spark_mysql_time = (
    pyspark_processing_time
    + mysql_write_time
)

# =====================================
# Results
# =====================================

print()
print("=" * 60)
print("S0 - PYSPARK RESULT")
print("=" * 60)

print(
    f"Execution status        : "
    f"{status}"
)

print(
    f"PySpark processing time : "
    f"{pyspark_processing_time:.2f} seconds"
)

print(
    f"Local MySQL write time  : "
    f"{mysql_write_time:.2f} seconds"
)

print(
    f"Spark + MySQL time      : "
    f"{spark_mysql_time:.2f} seconds"
)

print(
    f"Output records          : "
    f"{record_count}"
)

print(
    f"Average CPU utilization : "
    f"{average_cpu:.2f}%"
)

print(
    f"Peak CPU utilization    : "
    f"{peak_cpu:.2f}%"
)

print(
    f"Average memory usage    : "
    f"{average_memory:.2f}%"
)

print(
    f"Peak memory usage       : "
    f"{peak_memory:.2f}%"
)

if error_message:
    print(
        f"Error                   : "
        f"{error_message}"
    )

print("=" * 60)

if status == "FAILED":
    sys.exit(1)
