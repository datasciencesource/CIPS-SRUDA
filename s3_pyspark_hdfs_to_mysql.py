"""S3 Script-2: baseline + verification + decryption + DB check + audit.

Required: LOCAL_DB_PASSWORD, SOURCE_TABLE, S2_AES_KEY_B64.
Use the SAME key as S3 Sqoop. No S3_AUTH_TOKEN is needed.
Run with spark-submit and the existing MySQL Connector/J jar.
Append mode is retained: the script never clears the destination table.
A failed JDBC write may leave partial output; no automatic retry is made.
Decryption time includes HDFS download. Spark startup/cleanup and summary
saving are outside cumulative component totals and reported separately.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

HDFS_INPUT = "hdfs:///security_lab/s3/part-00000.enc"
MYSQL_URL = ("jdbc:mysql://127.0.0.1:3306/dbtest"
             "?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
             "&connectTimeout=10000&socketTimeout=30000")
MYSQL_TABLE = "table_stock"
MYSQL_USER = "usertest"
DATASETS = {
    "table_stock100": ("Small", 125),
    "table_stock20K": ("Medium", 24858),
    "table_stock4M": ("Large", 4248576),
}

def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def cpu_values():
    with open("/proc/stat") as f:
        values = list(map(int, f.readline().split()[1:9]))
    return sum(values), values[3] + values[4]


def memory_percent():
    with open("/proc/meminfo") as f:
        values = {line.split(":")[0]: int(line.split()[1]) for line in f}
    return (1 - values["MemAvailable"] / values["MemTotal"]) * 100


class Monitor:
    def __init__(self):
        self.cpu, self.memory = [], []
        self.error = None
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            old_total, old_idle = cpu_values()
            self.memory.append(memory_percent())
            while not self.stop.wait(0.5):
                total, idle = cpu_values()
                if total > old_total:
                    self.cpu.append((1 - (idle - old_idle) / (total - old_total)) * 100)
                self.memory.append(memory_percent())
                old_total, old_idle = total, idle
        except Exception as exc:
            self.error = str(exc)



def decrypt_hdfs_file(work, key):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    encrypted = work / "data.enc"
    decrypted = work / "verified_input.csv"
    result = subprocess.run(["hdfs", "dfs", "-get", HDFS_INPUT, str(encrypted)])
    if result.returncode:
        raise RuntimeError("Cannot download S3 HDFS dataset; see terminal output.")
    payload = encrypted.read_bytes()
    if len(payload) <= 28:
        raise RuntimeError("S3 encrypted dataset is empty or invalid.")
    try:
        plaintext = AESGCM(key).decrypt(payload[:12], payload[12:], None)
    except InvalidTag:
        raise RuntimeError("AES-GCM authentication failed: wrong key or altered data.") from None
    decrypted.write_bytes(plaintext)
    return decrypted


def verify_hash_chain(path, expected):
    previous_hash, count = "GENESIS", 0
    with path.open("r", encoding="utf-8") as source:
        for line in source:
            row = line.rstrip("\r\n")
            if not row:
                continue
            try:
                original_row, stored_hash = row.rsplit(",", 1)
            except ValueError:
                raise RuntimeError(f"Missing hash at record {count + 1}.") from None
            calculated = hashlib.sha256(
                f"{previous_hash}|{original_row}".encode("utf-8")
            ).hexdigest()
            if calculated != stored_hash:
                raise RuntimeError(f"Hash verification failed at record {count + 1}.")
            previous_hash = stored_hash
            count += 1
    if count != expected:
        raise RuntimeError(f"Expected {expected} verified records but found {count}.")
    return count


def check_mysql_connectivity(spark, password):
    # Use the same JDBC driver, database, and credentials as the output write.
    connection = statement = result = None
    try:
        properties = spark._jvm.java.util.Properties()
        properties.setProperty("user", MYSQL_USER)
        properties.setProperty("password", password)
        driver = spark._jvm.com.mysql.cj.jdbc.Driver()
        connection = driver.connect(MYSQL_URL, properties)
        if connection is None:
            raise RuntimeError("JDBC driver could not open the local MySQL connection.")
        statement = connection.createStatement()
        statement.setQueryTimeout(10)
        result = statement.executeQuery("SELECT 1")
        if not result.next() or result.getInt(1) != 1:
            raise RuntimeError("Local MySQL connectivity check failed.")
    finally:
        for resource in (result, statement, connection):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass


def process_data(spark, path, expected):
    from pyspark import StorageLevel
    data = (spark.read
            .schema("id INT, product_id INT, purchasing_price DOUBLE, "
                    "quantity DOUBLE, stock_date TIMESTAMP, row_hash STRING")
            .option("header", "false")
            .option("timestampFormat", "yyyy-MM-dd HH:mm:ss.S")
            .option("mode", "FAILFAST")
            .csv(path.resolve().as_uri())
            .persist(StorageLevel.MEMORY_AND_DISK))
    try:
        count = data.count()
        if count != expected:
            raise RuntimeError(f"Expected {expected} parsed records but found {count}.")
        return data, count
    except Exception:
        data.unpersist()
        raise


def write_mysql(data, password):
    (data.drop("row_hash").coalesce(1).write.format("jdbc")
     .option("url", MYSQL_URL).option("dbtable", MYSQL_TABLE)
     .option("user", MYSQL_USER).option("password", password)
     .option("driver", "com.mysql.cj.jdbc.Driver")
     .mode("append").save())


def main():
    os.umask(0o077)
    source_table = os.getenv("SOURCE_TABLE", "")
    scale, expected = DATASETS.get(source_table, ("UNKNOWN", None))
    password = os.getenv("LOCAL_DB_PASSWORD", "")
    key_text = os.getenv("S2_AES_KEY_B64", "")
    run_id = uuid.uuid4().hex
    audit_path = Path(os.getenv("S3_AUDIT_LOG", "/tmp/s3_audit.log"))
    results_dir = Path(os.getenv("S3_RESULTS_DIR", "/tmp/s3_results"))
    timings = {name: 0.0 for name in (
        "pyspark_processing", "mysql_write", "hash_verification", "decryption",
        "mysql_connectivity", "audit_logging")}
    stages = {name: "NOT RUN" for name in timings if name != "audit_logging"}
    audit_status = "NOT RUN"
    status, error = "FAILED", "N/A"
    records = verified_records = 0
    write_state = "NOT ATTEMPTED"
    spark = data = None
    spark_startup_time = spark_cleanup_time = 0.0
    cleanup_errors = []
    start_label = now()
    workflow_start = time.perf_counter()
    monitor = Monitor()

    def redact(message):
        text = str(message)
        for secret in (password, key_text):
            if secret:
                text = text.replace(secret, "[REDACTED]")
        return text

    def audit(event, event_status, message="N/A", **details):
        nonlocal audit_status
        started = time.perf_counter()
        try:
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            entry = dict(timestamp=now(), run_id=run_id, strategy="S3", script="pyspark",
                         dataset=scale, source_table=source_table, event=event,
                         status=event_status, message=redact(message), **details)
            with audit_path.open("a", encoding="utf-8") as log:
                log.write(json.dumps(entry) + "\n")
                log.flush()
                os.fsync(log.fileno())
            if audit_status != "FAIL":
                audit_status = "PASS"
        except Exception:
            audit_status = "FAIL"
            raise RuntimeError("Audit logging failed; workflow blocked.") from None
        finally:
            timings["audit_logging"] += time.perf_counter() - started

    def stage(name, action):
        audit(name.upper() + "_STARTED", "INFO")
        started = time.perf_counter()
        try:
            value = action()
        except Exception:
            stages[name] = "FAIL"
            raise
        else:
            stages[name] = "PASS"
        finally:
            timings[name] = time.perf_counter() - started
        audit(name.upper(), "PASS", duration_seconds=timings[name])
        return value


    monitor.thread.start()
    try:
        audit("WORKFLOW_STARTED", "INFO")
        if not password or source_table not in DATASETS:
            raise ValueError("Set LOCAL_DB_PASSWORD and a valid SOURCE_TABLE.")
        try:
            key = base64.b64decode(key_text, validate=True)
            if len(key) != 32:
                raise ValueError
        except Exception:
            raise ValueError("S2_AES_KEY_B64 must decode to exactly 32 bytes.") from None
        started = time.perf_counter()
        try:
            from pyspark.sql import SparkSession
            spark = (SparkSession.builder
                     .appName("S3 Cumulative HDFS to Local MySQL")
                     .master("local[*]").getOrCreate())
            spark.sparkContext.setLogLevel("ERROR")
        finally:
            spark_startup_time = time.perf_counter() - started
        with tempfile.TemporaryDirectory(prefix="s3_pyspark_") as temporary:
            decrypted_file = stage("decryption", lambda: decrypt_hdfs_file(Path(temporary), key))
            verified_records = stage("hash_verification", lambda: verify_hash_chain(decrypted_file, expected))
            data, records = stage("pyspark_processing", lambda: process_data(spark, decrypted_file, expected))
            # Gate the write immediately before it starts.
            stage("mysql_connectivity", lambda: check_mysql_connectivity(spark, password))

            def save_output():
                nonlocal write_state
                write_state = "ATTEMPTED - COMPLETION UNKNOWN"
                write_mysql(data, password)
                write_state = "COMPLETED"

            stage("mysql_write", save_output)
        audit("WORKFLOW_COMPLETED", "PASS", "Script-2 complete; ALLOW downstream use.",
              records=records, verified_records=verified_records)
        status = "SUCCESS"
    except Exception as exc:
        error = redact(exc)
        try:
            audit("WORKFLOW_COMPLETED", "FAIL", error, decision="BLOCK",
                  stage_status=stages, mysql_write_state=write_state)
        except Exception as audit_exc:
            error += "; " + str(audit_exc)
    finally:
        started = time.perf_counter()
        for cleanup in ([data.unpersist] if data is not None else []) + ([spark.stop] if spark is not None else []):
            try:
                cleanup()
            except Exception as exc:
                cleanup_errors.append(redact(exc))
        spark_cleanup_time = time.perf_counter() - started
        monitor.stop.set()
        monitor.thread.join()

    end_label = now()
    wall_time = time.perf_counter() - workflow_start
    s0_script2_time = timings["pyspark_processing"] + timings["mysql_write"]
    s1_script2_time = s0_script2_time + timings["hash_verification"]
    s2_script2_time = s1_script2_time + timings["decryption"]
    s3_script2_time = s2_script2_time + timings["mysql_connectivity"] + timings["audit_logging"]

    def mean(values):
        return sum(values) / len(values) if values else None

    metrics = dict(
        run_id=run_id, strategy="S3", script="pyspark", dataset=scale,
        source_table=source_table, expected_records=expected, parsed_records=records,
        verified_records=verified_records,
        output_records=records if write_state == "COMPLETED" else None,
        mysql_write_state=write_state, mysql_output_independently_verified="NOT TESTED",
        start=start_label, end=end_label, status=status, error=error,
        component_seconds=timings,
        cumulative_seconds={"S0-Script-2": s0_script2_time, "S1-Script-2": s1_script2_time,
                            "S2-Script-2": s2_script2_time, "S3-Script-2": s3_script2_time},
        script_wall_seconds=wall_time, spark_startup_seconds=spark_startup_time,
        spark_cleanup_seconds=spark_cleanup_time, cleanup_errors=cleanup_errors,
        stage_status=stages, audit_status=audit_status, hdfs_input=HDFS_INPUT,
        throughput_records_per_second=records / s3_script2_time if status == "SUCCESS" and s3_script2_time else None,
        cpu_average_percent=mean(monitor.cpu), cpu_peak_percent=max(monitor.cpu, default=None),
        memory_average_percent=mean(monitor.memory), memory_peak_percent=max(monitor.memory, default=None),
        resource_scope="whole host/VM", monitoring_error=monitor.error,
        retries=0, pipeline_total_seconds=None,
        timing_note="Decryption includes HDFS download. Verification is added once. Audit timers exclude processing stages. Spark startup/cleanup and summary saving are outside cumulative totals. Values are components of this run, not separate S0-S2 experiments.",
    )
    result_path = results_dir / ("s3_pyspark_" + run_id + ".json")
    save_error = None
    try:
        results_dir.mkdir(parents=True, exist_ok=True)
        with result_path.open("x", encoding="utf-8") as output:
            json.dump(metrics, output, indent=2)
            output.write("\n")
    except Exception as exc:
        save_error = redact(exc)

    def show(label, value):
        print(f"{label:<42}: {value}")

    print("=" * 78)
    print("S3 - CUMULATIVE PYSPARK RESULT")
    print("=" * 78)
    for label, value in [("Run ID", run_id), ("Laboratory environment", "S3"),
                         ("Dataset scale", scale), ("Source table", source_table),
                         ("Workflow start time", start_label), ("Workflow end time", end_label),
                         ("Execution status", status)]:
        show(label, value)
    for label, value in [("S0-Script-2 time", s0_script2_time),
                         ("PySpark processing component", timings["pyspark_processing"]),
                         ("Local MySQL write time", timings["mysql_write"]),
                         ("Hash-verification time", timings["hash_verification"]),
                         ("S1-Script-2 total time", s1_script2_time),
                         ("AES-GCM decryption + download time", timings["decryption"]),
                         ("S2-Script-2 total time", s2_script2_time),
                         ("Local MySQL connectivity-check time", timings["mysql_connectivity"]),
                         ("Audit-logging time", timings["audit_logging"]),
                         ("S3-Script-2 total time", s3_script2_time),
                         ("Spark startup time (outside totals)", spark_startup_time),
                         ("Spark cleanup time (outside totals)", spark_cleanup_time),
                         ("Script wall-clock time", wall_time)]:
        show(label, f"{value:.6f} seconds")
    for name, value in stages.items():
        show(name.replace("_", " ").title() + " status", value)
    show("Audit logging", audit_status)
    show("Parsed records", records)
    show("Verified records", verified_records)
    show("Output records (JDBC write completed)", metrics["output_records"] if write_state == "COMPLETED" else "UNKNOWN / NOT WRITTEN")
    show("MySQL write state", write_state)
    show("Independent MySQL output verification", "NOT TESTED")
    show("Expected records", expected)
    rate = metrics["throughput_records_per_second"]
    show("Script-2 throughput (records/second)", f"{rate:.4f}" if rate is not None else "N/A")
    for label, field in [("Average CPU utilization", "cpu_average_percent"), ("Peak CPU utilization", "cpu_peak_percent"),
                         ("Average memory utilization", "memory_average_percent"), ("Peak memory utilization", "memory_peak_percent")]:
        value = metrics[field]
        show(label, f"{value:.2f}%" if value is not None else "N/A")
    show("Resource measurement scope", "Whole host/VM")
    show("Monitoring error", monitor.error or "N/A")
    show("Script-2 decision", "ALLOW" if status == "SUCCESS" and not save_error else "BLOCK")
    show("Number of script retries", 0)
    show("Error / failure message", error)
    show("Cleanup errors", "; ".join(cleanup_errors) or "N/A")
    show("Audit log file", audit_path)
    show("Measurement record", result_path if not save_error else "SAVE FAILED: " + save_error)
    show("Total pipeline time", "N/A - Script-1 and dashboard not measured here")
    print("=" * 78)
    return 0 if status == "SUCCESS" and not save_error else 1


if __name__ == "__main__":
    sys.exit(main())

