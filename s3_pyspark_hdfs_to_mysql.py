"""S3 Script-2: baseline + verification + decryption + DB check + audit.

Required: LOCAL_DB_PASSWORD, SOURCE_TABLE, S2_AES_KEY_B64.
Optional: LOCAL_DB_HOST (default 127.0.0.1), used for both JDBC check and write.
Use the SAME key as S3 Sqoop. No S3_AUTH_TOKEN is needed.
Run with spark-submit and the existing MySQL Connector/J jar.
Append mode is retained: the script never clears the destination table.
A failed JDBC write may leave partial output; no automatic retry is made.
Decryption time includes HDFS download. Spark startup/cleanup and summary
saving are outside cumulative component totals and reported separately.
S2 processing order is retained: decrypt, parse/count, verify, write.
S3 adds the connectivity gate before writing and timed audit events.
Resource monitoring excludes Spark startup and shutdown, as in S2.
Run the directory-check version of Sqoop first and retain its JSON in S3_RESULTS_DIR.
Only schema-3 ingestion results are accepted, preventing mixing the earlier
post-upload dataset-check measurement with the revised directory check.
PySpark automatically matches its input ciphertext to exactly one Sqoop JSON.
Optional S3_SQOOP_RESULT selects an explicit JSON; mismatches block writing.
Final Instrument 1 table combines both runs. Total is active component time,
not elapsed terminal-to-Superset time. Separate script metrics remain available.
"""
import base64
import hashlib
import json
import math
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
MYSQL_HOST = os.getenv("LOCAL_DB_HOST", "127.0.0.1").strip()
MYSQL_URL = (f"jdbc:mysql://{MYSQL_HOST}:3306/dbtest"
             "?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC")
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
    return decrypted, encrypted


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
        # Bound only the added S3 check; retain S2's URL for the data write.
        connection = driver.connect(
            MYSQL_URL + "&connectTimeout=10000&socketTimeout=30000", properties)
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



def print_instrument_tables(metrics, save_error):
    """Print Instrument 1 sections last, after the detailed JSON."""
    script = metrics["script"]
    number = 1 if script == "sqoop" else 2
    def formatted(value, digits=6):
        return "N/A" if value is None else f"{value:.{digits}f}"
    def table(headers, rows):
        print("| " + " | ".join(headers) + " |")
        print("| " + " | ".join("---" for _ in headers) + " |")
        for row in rows:
            print("| " + " | ".join(str(v).replace("|", "/").replace("\n", " ") for v in row) + " |")
    print("\nB. Performance Measurement")
    print(f"Current strategy: S3 | Script-{number}: {script} | Dataset: {metrics['dataset']}")
    rows = []
    for strategy in range(4):
        for part in (1, 2):
            label = f"S{strategy}-Script-{part}"
            value = metrics["cumulative_seconds"].get(label)
            rows.append((label, f"S{strategy}", "seconds",
                         formatted(value) if part == number else "N/A - other script"))
    rate = metrics.get("throughput_records_per_second")
    rows.extend([
        ("Local MySQL write time", "Current", "seconds",
         formatted(metrics["component_seconds"].get("mysql_write"))),
        ("Total pipeline time", "Current", "seconds", formatted(metrics.get("pipeline_total_seconds"))),
        ("Throughput", "Current", "records/second", formatted(rate) + " (this script only)" if rate is not None else "N/A"),
        ("HDFS storage size", "Current", "MB", formatted(metrics.get("hdfs_storage_mb"))),
        ("Output records", "Current", "records", metrics["output_records"] if metrics["output_records"] is not None else "N/A"),
        ("Average CPU utilization", "Current", "%", formatted(metrics["cpu_average_percent"], 2)),
        ("Peak CPU utilization", "Current", "%", formatted(metrics["cpu_peak_percent"], 2)),
        ("Average memory utilization", "Current", "%", formatted(metrics["memory_average_percent"], 2)),
        ("Peak memory utilization", "Current", "%", formatted(metrics["memory_peak_percent"], 2)),
    ])
    table(["Metric", "Strategy", "Unit", "Recorded Value"], rows)
    print("CPU/memory cover this script's monitoring window on the whole VM.")
    print("S0-S2 values are cumulative components of this S3 run.")
    print("S2-Script-2 = S1-Script-2 + decryption (verification counted once).")
    print("\nC. Execution Reliability")
    success = metrics["status"] == "SUCCESS" and not save_error
    issues = []
    if metrics["error"] != "N/A":
        issues.append(metrics["error"])
    if save_error:
        issues.append("Measurement save failed: " + save_error)
    abnormal = not success or bool(metrics.get("monitoring_error")) or bool(metrics.get("cleanup_errors"))
    if success and script == "sqoop":
        notes = (f"S3 ingestion completed; {metrics['output_records']} records hash-chained and encrypted; "
                 "HDFS target-directory check passed before ingestion; audit events recorded.")
    elif success:
        notes = (f"S3 processing completed; {metrics['verified_records']} records verified; "
                 f"JDBC write completed for {metrics['output_records']} records; "
                 "local DB connectivity checked and audit events recorded.")
    else:
        notes = "S3 workflow did not complete successfully. Inspect stage statuses before retrying."
    if script == "pyspark":
        notes += " MySQL write state: " + metrics["mysql_write_state"] + "."
    if metrics.get("monitoring_error"):
        notes += " Monitoring error: " + metrics["monitoring_error"]
    if metrics.get("cleanup_errors"):
        notes += " Cleanup errors: " + "; ".join(metrics["cleanup_errors"])
    table(["Field", "Entry", "Recorded Value"], [
        ("Execution status", "Success / Failure", "Success" if success else "Failure"),
        ("Retry required", "Yes / No", "No" if success else "Review failure before retrying"),
        ("Number of retries", "count", metrics["retries"]),
        ("Error / failure message", "text", "; ".join(issues) or "N/A"),
        ("Abnormal condition observed", "Yes / No", "Yes" if abnormal else "No"),
        ("Notes", "Text", notes),
    ])


def match_sqoop_result(encrypted_file, results_dir, source_table, expected):
    """Bind measurements to the exact ciphertext downloaded by this run.

    Explicit S3_SQOOP_RESULT wins. Otherwise require exactly one matching
    successful record; never choose an unrelated file by modification time.
    Matching is measurement bookkeeping, not an authorization mechanism.
    """
    digest = hashlib.sha256()
    with encrypted_file.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    fingerprint = digest.hexdigest()
    selected = os.getenv("S3_SQOOP_RESULT")
    paths = [Path(selected)] if selected else sorted(results_dir.glob("s3_sqoop_*.json"))
    matches = []
    for path in paths:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(record, dict):
                raise ValueError("Result is not a JSON object")
            if (record.get("measurement_schema_version") != 3
                    or record.get("hdfs_availability_scope") != "target-directory existence before ingestion"
                    or record.get("hdfs_upload_size_verified") != "PASS"
                    or record.get("ciphertext_sha256") != fingerprint
                    or record.get("strategy") != "S3" or record.get("script") != "sqoop"
                    or record.get("source_table") != source_table
                    or record.get("dataset") != DATASETS[source_table][0]
                    or record.get("expected_records") != expected
                    or record.get("output_records") != expected
                    or record.get("hdfs_bytes") != encrypted_file.stat().st_size
                    or record.get("hdfs_file") != "/security_lab/s3/part-00000.enc"
                    or record.get("status") != "SUCCESS"
                    or record.get("audit_status") != "PASS"
                    or any(record.get("stage_status", {}).get(name) != "PASS"
                           for name in ("sqoop", "hash", "encryption", "hdfs_availability"))):
                raise ValueError("Result does not match the successful S3 ingestion and ciphertext")
            components = record["component_seconds"]
            running = 0.0
            for level, names in enumerate((("sqoop",), ("hash",), ("encryption",),
                                           ("hdfs_availability", "audit_logging"))):
                for name in names:
                    value = components[name]
                    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                        raise ValueError("Invalid component timing")
                    running += value
                actual = record["cumulative_seconds"][f"S{level}-Script-1"]
                if not isinstance(actual, (int, float)) or not math.isfinite(actual) or not math.isclose(actual, running, abs_tol=1e-7):
                    raise ValueError("Inconsistent cumulative timing")
            if running <= 0 or not record.get("run_id"):
                raise ValueError("Missing run ID or positive duration")
            matches.append((path, record))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            if selected:
                raise RuntimeError(f"Selected Sqoop result is invalid: {exc}") from None
    if len(matches) != 1:
        raise RuntimeError(
            "Cannot uniquely match this encrypted input to a successful updated Sqoop result. "
            "Run the updated Sqoop script first, keep its JSON, and use the same S3_RESULTS_DIR; "
            "or set S3_SQOOP_RESULT to its exact JSON path. MySQL write has not started.")
    path, record = matches[0]
    return record, str(path.resolve()), fingerprint


def combine_results(sqoop, pyspark):
    """Sum disjoint component timings; count the final dataset only once."""
    if sqoop["status"] != "SUCCESS" or pyspark["status"] != "SUCCESS":
        raise ValueError("Combined successful measurements require both scripts to succeed")
    if sqoop["output_records"] != pyspark["output_records"]:
        raise ValueError("Output record counts differ")
    total = sqoop["cumulative_seconds"]["S3-Script-1"] + pyspark["cumulative_seconds"]["S3-Script-2"]
    result = dict(
        measurement_schema_version=3,
        hdfs_availability_scope=sqoop["hdfs_availability_scope"],
        status="SUCCESS", sqoop_run_id=sqoop["run_id"], pyspark_run_id=pyspark["run_id"],
        cumulative_seconds={**sqoop["cumulative_seconds"], **pyspark["cumulative_seconds"]},
        total_pipeline_seconds=total,
        throughput_records_per_second=pyspark["output_records"] / total,
        output_records=pyspark["output_records"],
        hdfs_bytes=sqoop["hdfs_bytes"], hdfs_storage_mb=sqoop["hdfs_bytes"] / 1_000_000,
        mysql_write_seconds=pyspark["component_seconds"]["mysql_write"],
        script_wall_seconds_sum=sqoop["script_wall_seconds"] + pyspark["script_wall_seconds"],
        timing_scope="Sum of S3 component totals; excludes gaps, Spark startup/cleanup, result matching/saving, and Superset",
        resource_scope="Whole VM; pooled 0.5-second samples from both active monitoring windows; excludes gap and Spark startup/cleanup",
        mysql_output_independently_verified=pyspark["mysql_output_independently_verified"],
        automatic_retries=sqoop["retries"] + pyspark["retries"],
    )
    for resource in ("cpu", "memory"):
        counts = [r.get(resource + "_sample_count", 0) for r in (sqoop, pyspark)]
        peaks = [r.get(resource + "_peak_percent") for r in (sqoop, pyspark)]
        valid = all(isinstance(n, int) and n > 0 for n in counts) and all(
            not r.get("monitoring_error") for r in (sqoop, pyspark))
        result[resource + "_average_percent"] = (
            sum(r[resource + "_sample_sum"] for r in (sqoop, pyspark)) / sum(counts) if valid else None)
        result[resource + "_peak_percent"] = max(peaks) if valid and all(v is not None for v in peaks) else None
    result["resource_measurement_status"] = "COMPLETE" if all(
        result[x + "_average_percent"] is not None for x in ("cpu", "memory")) else "INCOMPLETE"
    return result


def print_combined_instrument(metrics, save_error):
    result = metrics.get("pipeline_result")
    print("\nB. Performance Measurement - INSTRUMENT 1 - COMBINED S3 PIPELINE RESULT")
    if result is None:
        print("Combined result unavailable: " + metrics.get("pipeline_measurement_error", "Pipeline did not complete"))
        return
    def fmt(value, digits=6):
        return "N/A - incomplete monitoring" if value is None else f"{value:.{digits}f}"
    rows = [(f"S{s}-Script-{part}", f"S{s}", "seconds",
             fmt(result["cumulative_seconds"][f"S{s}-Script-{part}"]))
            for s in range(4) for part in (1, 2)]
    rows += [
        ("Local MySQL write time", "Current", "seconds", fmt(result["mysql_write_seconds"])),
        ("Total pipeline time", "Current", "seconds", fmt(result["total_pipeline_seconds"])),
        ("Throughput", "Current", "records/second", fmt(result["throughput_records_per_second"])),
        ("HDFS storage size", "Current", "MB", fmt(result["hdfs_storage_mb"])),
        ("Output records", "Current", "records", result["output_records"]),
    ]
    for label, field in (("Average CPU utilization", "cpu_average_percent"),
                         ("Peak CPU utilization", "cpu_peak_percent"),
                         ("Average memory utilization", "memory_average_percent"),
                         ("Peak memory utilization", "memory_peak_percent")):
        rows.append((label, "Current", "%", fmt(result[field], 2)))
    print("| Metric | Strategy | Unit | Recorded Value |")
    print("| --- | --- | --- | --- |")
    for row in rows:
        print("| " + " | ".join(map(str, row)) + " |")
    print("Timing scope: " + result["timing_scope"])
    print("Resource scope: " + result["resource_scope"])
    print("S0-S2 rows are subtotals of this S3 run, not separate strategy experiments.")
    print("HDFS size is the encrypted file only; decimal MB, excluding raw staging and replicas.")
    print("Output count is based on completed JDBC write; independent MySQL readback: " + result["mysql_output_independently_verified"])
    print("Automatic retries: " + str(result["automatic_retries"]) + "; record manual reruns separately.")
    print("Resource measurement: " + result["resource_measurement_status"])
    print("Measurement file: " + ("SAVE FAILED: " + save_error if save_error else metrics["result_file"]))


def main():
    print("Starting S3 PySpark: decryption, processing, verification, MySQL check/write and audit logging.", flush=True)
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
    sqoop_result = None
    sqoop_result_path = ciphertext_sha256 = None
    result_matching_seconds = 0.0
    start_label = now()
    workflow_start = time.perf_counter()
    monitor = Monitor()
    monitor_started = False

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
        monitor.thread.start()
        monitor_started = True
        with tempfile.TemporaryDirectory(prefix="s3_pyspark_") as temporary:
            decrypted_file, encrypted_file = stage("decryption", lambda: decrypt_hdfs_file(Path(temporary), key))
            # Measurement matching is outside all S0-S3 component totals.
            match_start = time.perf_counter()
            try:
                sqoop_result, sqoop_result_path, ciphertext_sha256 = match_sqoop_result(
                    encrypted_file, results_dir, source_table, expected)
            finally:
                result_matching_seconds = time.perf_counter() - match_start
            audit("SQOOP_RESULT_MATCHED", "PASS", sqoop_run_id=sqoop_result["run_id"])

            data, records = stage("pyspark_processing", lambda: process_data(spark, decrypted_file, expected))
            verified_records = stage("hash_verification", lambda: verify_hash_chain(decrypted_file, expected))
            # Gate the write immediately before it starts.
            stage("mysql_connectivity", lambda: check_mysql_connectivity(spark, password))

            def save_output():
                nonlocal write_state
                write_state = "ATTEMPTED - COMPLETION UNKNOWN"
                write_mysql(data, password)
                write_state = "COMPLETED"

            stage("mysql_write", save_output)
        audit("WORKFLOW_COMPLETED", "PASS", "Script-2 complete; ALLOW downstream use.",
              decision="ALLOW", records=records, verified_records=verified_records)
        status = "SUCCESS"
    except Exception as exc:
        error = redact(exc)
        try:
            audit("WORKFLOW_COMPLETED", "FAIL", error, decision="BLOCK",
                  stage_status=stages, mysql_write_state=write_state)
        except Exception as audit_exc:
            error += "; " + str(audit_exc)
    finally:
        monitor.stop.set()
        if monitor_started:
            monitor.thread.join()
        started = time.perf_counter()
        for cleanup in ([data.unpersist] if data is not None else []) + ([spark.stop] if spark is not None else []):
            try:
                cleanup()
            except Exception as exc:
                cleanup_errors.append(redact(exc))
        spark_cleanup_time = time.perf_counter() - started

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
        monitoring_window="after Spark startup through workflow completion, before Spark cleanup",
        cpu_sample_count=len(monitor.cpu), memory_sample_count=len(monitor.memory),
        cpu_sample_sum=sum(monitor.cpu), memory_sample_sum=sum(monitor.memory),
        retries=0, pipeline_total_seconds=None,
        measurement_schema_version=3, ciphertext_sha256=ciphertext_sha256,
        sqoop_result_file=sqoop_result_path,
        sqoop_run_id=sqoop_result["run_id"] if sqoop_result else None,
        result_matching_seconds=result_matching_seconds,
        pipeline_result=None, pipeline_measurement_error="Pipeline did not complete successfully",

        timing_note="Decryption includes HDFS download. Verification is added once. Audit timers exclude processing stages. Spark startup/cleanup and summary saving are outside cumulative totals. Values are components of this run, not separate S0-S2 experiments.",
    )
    result_path = results_dir / ("s3_pyspark_" + run_id + ".json")
    metrics["result_file"] = str(result_path.resolve())
    if status == "SUCCESS" and sqoop_result is not None:
        metrics["pipeline_result"] = combine_results(sqoop_result, metrics)
        metrics["pipeline_total_seconds"] = metrics["pipeline_result"]["total_pipeline_seconds"]
        metrics["pipeline_throughput_records_per_second"] = metrics["pipeline_result"]["throughput_records_per_second"]
        metrics["pipeline_measurement_error"] = None
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
                         ("Strategy under test", "S3"),
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
    show("S0 baseline workflow", "RETAINED")
    show("S1 hash-chain verification", stages["hash_verification"])
    show("S2 AES-GCM decryption", stages["decryption"])
    show("S3 local DB availability check", stages["mysql_connectivity"])
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
    show("Abnormal condition observed", "YES" if status != "SUCCESS" or save_error or monitor.error or cleanup_errors else "NO")
    show("Error / failure message", error)
    show("Cleanup errors", "; ".join(cleanup_errors) or "N/A")
    show("Audit log file", audit_path)
    show("Measurement record", result_path if not save_error else "SAVE FAILED: " + save_error)
    total = metrics["pipeline_total_seconds"]
    show("Total pipeline processing time", f"{total:.6f} seconds" if total is not None else "N/A - workflow incomplete")
    show("Result matching time (outside totals)", f"{result_matching_seconds:.6f} seconds")
    print("=" * 78)
    print("SAVED JSON RESULT" if not save_error else "JSON RESULT - FILE SAVE FAILED")
    if not save_error:
        print(f"File: {result_path}")
    print(json.dumps(metrics, indent=2))
    print("=" * 78)
    print_instrument_tables(metrics, save_error)
    print_combined_instrument(metrics, save_error)
    return 0 if status == "SUCCESS" and not save_error else 1


if __name__ == "__main__":
    sys.exit(main())
