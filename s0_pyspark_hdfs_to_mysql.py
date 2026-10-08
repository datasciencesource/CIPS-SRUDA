"""S0 baseline measurements for Instrument 1; run Sqoop then PySpark.
Required: SOURCE_TABLE and REMOTE_DB_PASSWORD (Sqoop) / LOCAL_DB_PASSWORD (PySpark).
Optional: REMOTE_DB_HOST, LOCAL_DB_HOST, S0_RESULTS_DIR (default /tmp/s0_results),
S0_SQOOP_RESULT (explicit Sqoop JSON path).
No AES key, hash chain, S3 availability gate or security audit log is used.
Sqoop retains --delete-target-dir: it replaces /security_lab/s0 on each import.
An _s0_run.json sidecar identifies the ingestion run. It is measurement metadata,
not cryptographic integrity protection. Never edit/replace HDFS input during a run.
Both scripts print saved JSON and Instrument 1 Tables B/C; PySpark combines them.
Total = Sqoop import + Spark parse/count + JDBC write. Excludes metadata work,
Spark startup/cleanup, manual gaps, result saving and Superset.
Storage = sum of part-file bytes / 1,000,000; excludes marker and replicas.
CPU/memory samples measure the whole VM. Writes append; no automatic retry.
"""
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

HDFS_TARGET = "/security_lab/s0"
HDFS_INPUT = "hdfs:///security_lab/s0/part*"
HDFS_MARKER = HDFS_TARGET + "/_s0_run.json"
DATASETS = {
    "table_stock100": ("Small", 125),
    "table_stock20K": ("Medium", 24858),
    "table_stock4M": ("Large", 4248576),
}

MYSQL_HOST = os.getenv("LOCAL_DB_HOST", "127.0.0.1").strip()
MYSQL_URL = (f"jdbc:mysql://{MYSQL_HOST}:3306/dbtest"
             "?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC")
MYSQL_TABLE = "table_stock"
MYSQL_USER = "usertest"

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

class Measurement:
    def __init__(self, script, names, password_variable):
        os.umask(0o077)
        self.password = os.getenv(password_variable, "")
        self.password_variable = password_variable
        self.source = os.getenv("SOURCE_TABLE", "")
        scale, self.expected = DATASETS.get(self.source, ("UNKNOWN", None))
        self.directory = Path(os.getenv("S0_RESULTS_DIR", "/tmp/s0_results"))
        self.monitor = Monitor()
        self.monitor_started = False
        self.started = time.perf_counter()
        self.record = dict(
            measurement_schema_version=1, run_id=uuid.uuid4().hex,
            strategy="S0", script=script, dataset=scale, source_table=self.source,
            expected_records=self.expected, output_records=None,
            start=now(), status="FAILED", error="N/A",
            component_seconds={name: 0.0 for name in names},
            stage_status={name: "NOT RUN" for name in names},
            retries=0, pipeline_total_seconds=None, cleanup_errors=[],
            hdfs_bytes=None, hdfs_storage_mb=None,
            resource_scope="whole host/VM",
        )

    def validate(self):
        if not self.password or self.source not in DATASETS:
            raise ValueError(f"Set {self.password_variable} and a valid SOURCE_TABLE.")

    def redact(self, message):
        text = str(message) or type(message).__name__
        for secret in (self.password,):
            if secret:
                text = text.replace(secret, "[REDACTED]")
        return text

    def start_monitor(self):
        self.monitor.thread.start()
        self.monitor_started = True

    def stop_monitor(self):
        self.monitor.stop.set()
        if self.monitor_started:
            self.monitor.thread.join()

    def stage(self, name, action):
        print(f"Starting {name}...", flush=True)
        started = time.perf_counter()
        try:
            value = action()
        except Exception:
            self.record["stage_status"][name] = "FAIL"
            raise
        else:
            self.record["stage_status"][name] = "PASS"
            return value
        finally:
            self.record["component_seconds"][name] = time.perf_counter() - started

    def finish(self):
        r = self.record
        r["end"] = now()
        r["script_wall_seconds"] = time.perf_counter() - self.started
        t = r["component_seconds"]
        part = 1 if r["script"] == "sqoop" else 2
        total = t["sqoop"] if part == 1 else t["pyspark_processing"] + t["mysql_write"]
        r["cumulative_seconds"] = {f"S0-Script-{part}": total}
        r["throughput_records_per_second"] = r["output_records"] / total if r["status"] == "SUCCESS" and total > 0 else None
        for resource, samples in (("cpu",self.monitor.cpu),("memory",self.monitor.memory)):
            r[resource + "_sample_count"] = len(samples)
            r[resource + "_sample_sum"] = sum(samples)
            r[resource + "_average_percent"] = sum(samples)/len(samples) if samples else None
            r[resource + "_peak_percent"] = max(samples) if samples else None
        r["monitoring_error"] = self.monitor.error
        r["monitoring_window"] = "Sqoop import only" if part == 1 else "Spark parse/count and JDBC write only; excludes metadata matching and Spark startup/cleanup"
        r["resource_measurement_status"] = "COMPLETE" if self.monitor.cpu and self.monitor.memory and not self.monitor.error else "INCOMPLETE"
        r["timing_note"] = "Total sums Sqoop import, Spark parse/count and JDBC write. Metadata matching/measurement, Spark startup/cleanup, manual gaps, result saving and Superset excluded. No S1-S3 controls or timings."

    def save_and_show(self):
        r = self.record
        path = self.directory / f"s0_{r['script']}_{r['run_id']}.json"
        r["result_file"] = str(path.resolve())
        save_error = None
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8") as output:
                json.dump(r, output, indent=2, allow_nan=False)
                output.write("\n")
        except Exception as exc:
            save_error = self.redact(exc)
        print("=" * 76)
        print(f"S0 - CUMULATIVE {r['script'].upper()} RESULT")
        print(f"Execution status: {r['status']} | Run ID: {r['run_id']}")
        for name, value in r["component_seconds"].items():
            print(f"{name:<30}: {value:.6f} seconds | {r['stage_status'][name]}")
        print("SAVED JSON RESULT" if not save_error else "JSON RESULT - SAVE FAILED: " + save_error)
        print("File: " + str(path))
        print(json.dumps(r, indent=2, allow_nan=False))
        print_instrument_tables(r, save_error)
        if r["script"] == "pyspark":
            print_combined_instrument(r, save_error)
        return 0 if r["status"] == "SUCCESS" and not save_error else 1

def fmt(value, digits=6):
    return "N/A" if value is None else f"{value:.{digits}f}"

def table(headers, rows):
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        print("| " + " | ".join(str(v).replace("|", "/").replace("\n", " ").replace("\r", " ") for v in row) + " |")

def print_instrument_tables(r, save_error):
    part = 1 if r["script"] == "sqoop" else 2
    print(f"\nB. Performance Measurement | S0 | Script-{part} | {r['dataset']}")
    rows = []
    for strategy in range(4):
        for number in (1,2):
            label = f"S{strategy}-Script-{number}"
            value = "N/A - not tested" if strategy > 0 else (fmt(r["cumulative_seconds"].get(label)) if number == part else "N/A - other script")
            rows.append((label, f"S{strategy}", "seconds", value))
    total = fmt(r.get("pipeline_total_seconds"))
    if part == 1:
        total = "PENDING - matching PySpark run" if r["status"] == "SUCCESS" and not save_error else "N/A - ingestion incomplete"
    rows.extend([
        ("Local MySQL write time", "Current", "seconds", fmt(r["component_seconds"].get("mysql_write"))),
        ("Total pipeline time", "Current", "seconds", total),
        ("Throughput", "Current", "records/second", fmt(r["throughput_records_per_second"]) + " (this script only)"),
        ("HDFS storage size", "Current", "MB", fmt(r.get("hdfs_storage_mb"))),
        ("Output records", "Current", "records", r["output_records"] if r["output_records"] is not None else "N/A"),
    ])
    for label, field in (("Average CPU utilization","cpu_average_percent"), ("Peak CPU utilization","cpu_peak_percent"),
                         ("Average memory utilization","memory_average_percent"), ("Peak memory utilization","memory_peak_percent")):
        rows.append((label,"Current","%",fmt(r[field],2)))
    table(["Metric","Strategy","Unit","Recorded Value"],rows)
    print("S0 baseline only; S1/S2/S3 are not tested.")
    print("Resources: whole VM, 0.5-second samples. Storage: part files only, decimal MB; excludes marker and replicas.")
    print("\nC. Execution Reliability")
    success = r["status"] == "SUCCESS"
    issues = [r["error"]] if r["error"] != "N/A" else []
    if save_error:
        issues.append("Measurement save failed: " + save_error)
    notes = "Stages: " + "; ".join(f"{k}={v}" for k,v in r["stage_status"].items())
    if part == 2:
        notes += "; MySQL write: " + r["mysql_write_state"] + "; independent MySQL readback: NOT TESTED"
    notes += "; resource measurement: " + r["resource_measurement_status"]
    abnormal = not success or save_error or r["monitoring_error"] or r["cleanup_errors"]
    table(["Field","Entry","Recorded Value"],[
        ("Execution status","Success / Failure","Success" if success else "Failure"),
        ("Retry required","Yes / No","No" if success and not save_error else "Review failure before retrying"),
        ("Number of retries","count",0),
        ("Error / failure message","text","; ".join(issues) or "N/A"),
        ("Abnormal condition observed","Yes / No","Yes" if abnormal else "No"),
        ("Notes","Text",notes),
    ])
    print("Automatic retries only; record manual reruns separately.")

def run_command(args, **kwargs):
    # Do not include command arguments in exceptions (credential hygiene).
    result = subprocess.run(args, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed with exit code {result.returncode}; see terminal output.")
    return result

def part_manifest():
    result = run_command(["hdfs","dfs","-ls",HDFS_TARGET + "/part*"],
                         stdout=subprocess.PIPE, text=True, timeout=60)
    entries = []
    for line in result.stdout.splitlines():
        fields = line.split(None, 7)
        if len(fields) == 8 and fields[0].startswith("-"):
            entries.append(dict(path=fields[7], bytes=int(fields[4]), modified=fields[5]+" "+fields[6]))
    if not entries or sum(e["bytes"] for e in entries) <= 0:
        raise RuntimeError("No nonempty S0 part-file dataset found.")
    return sorted(entries, key=lambda e:e["path"])


def read_marker():
    result = run_command(["hdfs","dfs","-cat",HDFS_MARKER],
                         stdout=subprocess.PIPE, text=True, timeout=60)
    marker = json.loads(result.stdout)
    if not isinstance(marker, dict):
        raise RuntimeError("Invalid S0 run metadata.")
    return marker

def process_data(spark, expected):
    from pyspark import StorageLevel
    data = (spark.read
            .schema("id INT, product_id INT, purchasing_price DOUBLE, "
                    "quantity DOUBLE, stock_date TIMESTAMP")
            .option("header", "false")
            .option("timestampFormat", "yyyy-MM-dd HH:mm:ss.S")
            .option("mode", "FAILFAST")
            .csv(HDFS_INPUT)
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
    (data.coalesce(1).write.format("jdbc")
     .option("url", MYSQL_URL).option("dbtable", MYSQL_TABLE)
     .option("user", MYSQL_USER).option("password", password)
     .option("driver", "com.mysql.cj.jdbc.Driver")
     .mode("append").save())

def combine_results(sqoop, pyspark):
    """Sum disjoint component timings; count the final dataset only once."""
    if sqoop["status"] != "SUCCESS" or pyspark["status"] != "SUCCESS":
        raise ValueError("Combined successful measurements require both scripts to succeed")
    if sqoop["output_records"] != pyspark["output_records"]:
        raise ValueError("Output record counts differ")
    total = sqoop["cumulative_seconds"]["S0-Script-1"] + pyspark["cumulative_seconds"]["S0-Script-2"]
    result = dict(
        measurement_schema_version=1,
        status="SUCCESS", sqoop_run_id=sqoop["run_id"], pyspark_run_id=pyspark["run_id"],
        cumulative_seconds={**sqoop["cumulative_seconds"], **pyspark["cumulative_seconds"]},
        total_pipeline_seconds=total,
        throughput_records_per_second=pyspark["output_records"] / total,
        output_records=pyspark["output_records"],
        hdfs_bytes=sqoop["hdfs_bytes"], hdfs_storage_mb=sqoop["hdfs_bytes"] / 1_000_000,
        mysql_write_seconds=pyspark["component_seconds"]["mysql_write"],
        script_wall_seconds_sum=sqoop["script_wall_seconds"] + pyspark["script_wall_seconds"],
        timing_scope="Sum of S0 component totals; excludes gaps, Spark startup/cleanup, result matching/saving, and Superset",
        resource_scope="Whole VM; pooled 0.5-second samples from both active monitoring windows; excludes metadata matching, gaps and Spark startup/cleanup",
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
    print("\nB. Performance Measurement - INSTRUMENT 1 - COMBINED S0 PIPELINE RESULT")
    if result is None:
        print("Combined result unavailable: " + metrics.get("pipeline_measurement_error", "Pipeline did not complete"))
        return
    def fmt(value, digits=6):
        return "N/A - incomplete monitoring" if value is None else f"{value:.{digits}f}"
    rows = [(f"S{s}-Script-{part}", f"S{s}", "seconds",
             fmt(result["cumulative_seconds"][f"S{s}-Script-{part}"]))
            for s in range(1) for part in (1, 2)]
    rows += [(f"S{s}-Script-{part}", f"S{s}", "seconds", "N/A - not tested") for s in (1,2,3) for part in (1, 2)]
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
    print("S0 baseline only; S1/S2/S3 are not tested.")
    print("HDFS size is the part files only; decimal MB, excluding run metadata and replicas.")
    print("Output count is based on completed JDBC write; independent MySQL readback: " + result["mysql_output_independently_verified"])
    print("Automatic retries: " + str(result["automatic_retries"]) + "; record manual reruns separately.")
    print("Resource measurement: " + result["resource_measurement_status"])
    print("Measurement file: " + ("SAVE FAILED: " + save_error if save_error else metrics["result_file"]))

def match_sqoop_result(results_dir, source_table, expected):
    marker=read_marker()
    manifest=part_manifest()
    if (marker.get("strategy") != "S0" or marker.get("measurement_schema_version") != 1
            or marker.get("source_table") != source_table or marker.get("expected_records") != expected
            or marker.get("hdfs_part_manifest") != manifest):
        raise RuntimeError("S0 HDFS run metadata does not match the requested dataset/part files.")
    run_id=marker.get("run_id", "")
    if not re.fullmatch(r"[0-9a-f]{32}",run_id):
        raise RuntimeError("Invalid ingestion run ID.")
    selected=os.getenv("S0_SQOOP_RESULT")
    path=Path(selected) if selected else results_dir / f"s0_sqoop_{run_id}.json"
    record=json.loads(path.read_text(encoding="utf-8"))
    if (record.get("run_id") != run_id or record.get("strategy") != "S0"
            or record.get("measurement_schema_version") != 1 or record.get("script") != "sqoop"
            or record.get("source_table") != source_table or record.get("dataset") != DATASETS[source_table][0]
            or record.get("expected_records") != expected or record.get("output_records") != expected
            or record.get("status") != "SUCCESS" or record.get("stage_status",{}).get("sqoop") != "PASS"
            or record.get("hdfs_metadata_status") != "PASS" or record.get("hdfs_target") != HDFS_TARGET
            or record.get("hdfs_part_manifest") != manifest
            or record.get("hdfs_bytes") != sum(e["bytes"] for e in manifest)):
        raise RuntimeError("Sqoop JSON does not match the current successful S0 ingestion.")
    component=record["component_seconds"]["sqoop"]
    total=record["cumulative_seconds"]["S0-Script-1"]
    for value in (component,total):
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value <= 0:
            raise RuntimeError("Invalid Sqoop timing.")
    if not math.isclose(component,total,abs_tol=1e-7):
        raise RuntimeError("Inconsistent Sqoop total.")
    return record,str(path.resolve())


def main():
    print("Starting S0 baseline PySpark processing and MySQL write...",flush=True)
    m=Measurement("pyspark",("pyspark_processing","mysql_write"),"LOCAL_DB_PASSWORD")
    r=m.record
    r.update(parsed_records=0,mysql_write_state="NOT ATTEMPTED",mysql_output_independently_verified="NOT TESTED",
             hdfs_input=HDFS_INPUT,spark_startup_seconds=0.0,spark_cleanup_seconds=0.0,
             result_matching_seconds=0.0,sqoop_run_id=None,sqoop_result_file=None,
             pipeline_result=None,pipeline_measurement_error="Pipeline did not complete successfully",
             security_tests="Indicators 1-3 require separate ALLOW/DENY evidence; 4-12 not tested")
    spark=data=sqoop_result=None
    try:
        m.validate()
        started=time.perf_counter()
        try:
            sqoop_result,path=match_sqoop_result(m.directory,m.source,m.expected)
            r.update(sqoop_run_id=sqoop_result["run_id"],sqoop_result_file=path,
                     hdfs_bytes=sqoop_result["hdfs_bytes"],hdfs_storage_mb=sqoop_result["hdfs_bytes"]/1_000_000)
        finally:
            r["result_matching_seconds"]=time.perf_counter()-started
        started=time.perf_counter()
        try:
            from pyspark.sql import SparkSession
            spark=(SparkSession.builder.appName("S0 HDFS to Local MySQL").master("local[*]").getOrCreate())
            spark.sparkContext.setLogLevel("ERROR")
        finally:
            r["spark_startup_seconds"]=time.perf_counter()-started
        m.start_monitor()
        data,count=m.stage("pyspark_processing",lambda:process_data(spark,m.expected))
        r["parsed_records"]=count
        def save_output():
            r["mysql_write_state"]="ATTEMPTED - COMPLETION UNKNOWN"
            write_mysql(data,m.password)
            r["mysql_write_state"]="COMPLETED"
            r["output_records"]=count
        m.stage("mysql_write",save_output)
        r["status"]="SUCCESS"
    except Exception as exc:
        r["error"]=m.redact(exc)
    finally:
        m.stop_monitor()
        started=time.perf_counter()
        for cleanup in ([data.unpersist] if data is not None else [])+([spark.stop] if spark is not None else []):
            try:cleanup()
            except Exception as exc:r["cleanup_errors"].append(m.redact(exc))
        r["spark_cleanup_seconds"]=time.perf_counter()-started
    m.finish()
    if r["status"]=="SUCCESS" and sqoop_result is not None:
        try:
            r["pipeline_result"]=combine_results(sqoop_result,r)
            r["pipeline_total_seconds"]=r["pipeline_result"]["total_pipeline_seconds"]
            r["pipeline_throughput_records_per_second"]=r["pipeline_result"]["throughput_records_per_second"]
            r["pipeline_measurement_error"]=None
        except Exception as exc:r["pipeline_measurement_error"]=m.redact(exc)
    code=m.save_and_show()
    return code if r["pipeline_result"] is not None else 1


if __name__ == "__main__":
    sys.exit(main())
