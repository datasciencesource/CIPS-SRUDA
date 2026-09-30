from pyspark.sql import SparkSession

# 1. Start Spark
spark = (
    SparkSession.builder
    .appName("HDFS to Local MySQL")
    .master("local[*]")
    .getOrCreate()
)

spark.sparkContext.setLogLevel("ERROR")

try:
    # 2. Define the columns in the HDFS files
    schema = """
        id INT,
        product_id INT,
        purchasing_price DOUBLE,
        quantity DOUBLE,
        stock_date TIMESTAMP
    """

    # 3. Read all records from HDFS
    data = (
        spark.read
        .schema(schema)
        .option("header", "false")
        .option("timestampFormat", "yyyy-MM-dd HH:mm:ss.S")
        .option("mode", "FAILFAST")
        .csv("hdfs:///security_lab/s0/part*")
    )

    data.show(5, truncate=False)

    # 4. Insert all records into the existing local table
    (
        data.coalesce(1).write
        .format("jdbc")
        .option(
            "url",
            "jdbc:mysql://127.0.0.1:3306/dbtest"
            "?useSSL=false&allowPublicKeyRetrieval=true"
            "&serverTimezone=UTC"
        )
        .option("dbtable", "table_stock")
        .option("user", "usertest")
        .option("password", "Admin1111")
        .option("driver", "com.mysql.cj.jdbc.Driver")
        .mode("append")
        .save()
    )

    print("Data saved successfully to dbtest.table_stock")

finally:
    spark.stop()
