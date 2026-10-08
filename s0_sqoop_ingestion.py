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

REMOTE_DB_HOST = os.getenv("REMOTE_DB_HOST", "69.175.69.34").strip()
REMOTE_DB = f"jdbc:mysql://{REMOTE_DB_HOST}/sumrachna_hd"
USERNAME = "sumrachna_hd"

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


def import_sqoop(command, expected, redact):
    # Merge stderr/stdout to stream progress without filling an unread pipe.
    count = None
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding="utf-8", errors="replace")
    try:
        for line in process.stdout:
            print(redact(line), end="", flush=True)
            match = re.search(r"Retrieved ([0-9]+) records", line)
            if match:
                count = int(match.group(1))
        if process.wait() != 0:
            raise RuntimeError("Sqoop ingestion failed; see terminal output.")
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            process.wait()
    if count is None:
        raise RuntimeError("Sqoop succeeded but its retrieved-record count was not found; measurement incomplete.")
    if count != expected:
        raise RuntimeError(f"Expected {expected} records; Sqoop reported {count}.")
    return count


def main():
    print("Starting S0 baseline Sqoop ingestion...", flush=True)
    m = Measurement("sqoop", ("sqoop",), "REMOTE_DB_PASSWORD")
    r = m.record
    r.update(hdfs_target=HDFS_TARGET, hdfs_part_manifest=None, hdfs_metadata_status="NOT RUN",
             hdfs_record_count_basis="Sqoop retrieved-record log; independently checked by Spark later",
             metadata_seconds=0.0, security_tests="Indicators 1-3 require separate ALLOW/DENY evidence; 4-12 not tested")
    try:
        m.validate()
        with tempfile.TemporaryDirectory(prefix="s0_sqoop_") as tmp:
            work=Path(tmp)
            password_file=work / "password"
            password_file.write_text(m.password,encoding="utf-8")
            password_file.chmod(0o400)
            command=["sqoop","import","--connect",REMOTE_DB,"--username",USERNAME,
                     "--password-file",password_file.as_uri(),"--table",m.source,
                     "--target-dir",HDFS_TARGET,"--delete-target-dir"]
            m.start_monitor()
            try:
                r["output_records"]=m.stage("sqoop", lambda:import_sqoop(command,m.expected,m.redact))
            finally:
                m.stop_monitor()
            started=time.perf_counter()
            try:
                manifest=part_manifest()
                size=sum(e["bytes"] for e in manifest)
                marker=dict(measurement_schema_version=1,strategy="S0",run_id=r["run_id"],
                            source_table=m.source,expected_records=m.expected,
                            hdfs_part_manifest=manifest)
                marker_file=work / "_s0_run.json"
                marker_file.write_text(json.dumps(marker),encoding="utf-8")
                run_command(["hdfs","dfs","-put","-f",str(marker_file),HDFS_MARKER])
                r.update(hdfs_part_manifest=manifest,hdfs_bytes=size,hdfs_storage_mb=size/1_000_000,
                         hdfs_metadata_status="PASS")
            except Exception:
                r["hdfs_metadata_status"]="FAIL"
                raise
            finally:
                r["metadata_seconds"]=time.perf_counter()-started
        r["status"]="SUCCESS"
    except Exception as exc:
        r["error"]=m.redact(exc)
    finally:
        m.stop_monitor()
    m.finish()
    return m.save_and_show()


if __name__ == "__main__":
    sys.exit(main())
