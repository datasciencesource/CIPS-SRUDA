import os
import sys
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
# Start Spark
# =====================================

spark = (
    SparkSession.builder
    .appName("S0 HDFS to Local MySQL")
    .master("local[*]")
    .getOrCreate()
)

spark.sparkContext.setLogLevel("ERROR")

data = None

try:

    print("=" * 60)
    print("S0 - PYSPARK PROCESSING")
    print("=" * 60)

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

    # Keep processed data available for the
    # following MySQL write stage.
    data.persist(StorageLevel.MEMORY_AND_DISK)

    # Spark uses lazy execution.
    # count() forces actual HDFS processing.
    record_count = data.count()

    processing_end = time.time()

    pyspark_processing_time = (
        processing_end - processing_start
    )

    # Display sample records
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

    # =====================================
    # Results
    # =====================================

    print()
    print("=" * 60)
    print("S0 - PYSPARK RESULT")
    print("=" * 60)

    print("Execution status        : SUCCESS")

    print(
        f"PySpark processing time : "
        f"{pyspark_processing_time:.2f} seconds"
    )

    print(
        f"Local MySQL write time  : "
        f"{mysql_write_time:.2f} seconds"
    )

    print(
        f"Output records          : "
        f"{record_count}"
    )

    print(
        f"Spark + MySQL time      : "
        f"{pyspark_processing_time + mysql_write_time:.2f} seconds"
    )

    print("=" * 60)

except Exception as error:

    print()
    print("=" * 60)
    print("S0 - PYSPARK RESULT")
    print("=" * 60)

    print("Execution status        : FAILED")
    print(f"Error                   : {error}")

    print("=" * 60)

    sys.exit(1)

finally:

    if data is not None:
        data.unpersist()

    spark.stop()
