"""S1 cumulative measurements for Instrument 1.
Manual prerequisite: create /security_lab/s1. No automatic final-directory creation.
Required: SOURCE_TABLE and the relevant DB password. No AES key required.
Results: /tmp/s1_results (override S1_RESULTS_DIR).
For repeated identical inputs, set S1_SQOOP_RESULT to the exact ingestion JSON.
S0 timings are subtotals of this S1 run, not independent baseline experiments.
Hash-chain integrity assumes attackers do not recompute the entire chain.
No S3 connectivity/availability gate or security audit log is implemented.
"""
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

DATASETS = {
    "table_stock100": ("Small", 125),
    "table_stock20K": ("Medium", 24858),
    "table_stock4M": ("Large", 4248576),
}

REMOTE_DB_HOST = os.getenv("REMOTE_DB_HOST", "69.175.69.34").strip()
REMOTE_DB = f"jdbc:mysql://{REMOTE_DB_HOST}/sumrachna_hd"
USERNAME = "sumrachna_hd"
RAW_HDFS_TARGET = "/security_lab/s1_raw"
HDFS_TARGET = "/security_lab/s1"
HDFS_FILE = HDFS_TARGET + "/part-00000"

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
        self.directory = Path(os.getenv("S1_RESULTS_DIR", "/tmp/s1_results"))
        self.monitor = Monitor()
        self.monitor_started = False
        self.started = time.perf_counter()
        self.record = dict(
            measurement_schema_version=1, run_id=uuid.uuid4().hex,
            strategy="S1", script=script, dataset=scale, source_table=self.source,
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
        if part == 1:
            s0 = t["sqoop"]
            s1 = s0 + t["hash"]
        else:
            s0 = t["pyspark_processing"] + t["mysql_write"]
            s1 = s0 + t["hash_verification"]
        r["cumulative_seconds"] = {f"S{i}-Script-{part}": v for i, v in enumerate((s0,s1))}
        r["throughput_records_per_second"] = r["output_records"] / s1 if r["status"] == "SUCCESS" and s1 > 0 else None
        for resource, samples in (("cpu",self.monitor.cpu),("memory",self.monitor.memory)):
            r[resource + "_sample_count"] = len(samples)
            r[resource + "_sample_sum"] = sum(samples)
            r[resource + "_average_percent"] = sum(samples)/len(samples) if samples else None
            r[resource + "_peak_percent"] = max(samples) if samples else None
        r["monitoring_error"] = self.monitor.error
        r["monitoring_window"] = ("ingestion through hash generation/upload" if part == 1 else
            "after Spark startup through write/temporary cleanup; includes result matching; excludes Spark cleanup")
        r["resource_measurement_status"] = "COMPLETE" if self.monitor.cpu and self.monitor.memory and not self.monitor.error else "INCOMPLETE"
        r["timing_note"] = (
            "Hash includes HDFS read, chain generation, upload and size/fingerprint measurement. "
            "PySpark processing includes HDFS download and parse/count. Verification counted once. "
            "Spark startup/cleanup, matching/saving and manual gaps excluded from component totals. "
            "S0 values are subtotals of this S1 run, not separate experiments.")

    def save_and_show(self):
        r = self.record
        path = self.directory / f"s1_{r['script']}_{r['run_id']}.json"
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
        print(f"S1 - CUMULATIVE {r['script'].upper()} RESULT")
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
    print(f"\nB. Performance Measurement | S1 | Script-{part} | {r['dataset']}")
    rows = []
    for strategy in range(4):
        for number in (1,2):
            label = f"S{strategy}-Script-{number}"
            value = "N/A - not tested" if strategy >= 2 else (fmt(r["cumulative_seconds"].get(label)) if number == part else "N/A - other script")
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
    print("S0 values are cumulative subtotals of this S1 run; S2/S3 are not tested.")
    print("Resources: whole VM, 0.5-second samples. Storage: hash-chained file only, decimal MB.")
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

def digest_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def create_hash_chain(path, expected):
    previous_hash, count = "GENESIS", 0
    # stderr is inherited: a full stderr pipe cannot deadlock the reader.
    with open(path, "w", encoding="utf-8", newline="\n") as target:
        process = subprocess.Popen(
            ["hdfs", "dfs", "-cat", RAW_HDFS_TARGET + "/part*"],
            stdout=subprocess.PIPE, text=True, encoding="utf-8",
        )
        try:
            for line in process.stdout:
                row = line.rstrip("\r\n")
                if not row:
                    continue
                previous_hash = hashlib.sha256(
                    f"{previous_hash}|{row}".encode("utf-8")
                ).hexdigest()
                target.write(f"{row},{previous_hash}\n")
                count += 1
            if process.wait() != 0:
                raise RuntimeError("Unable to read raw HDFS data; see terminal output.")
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
                process.wait()
    if count != expected:
        raise RuntimeError(f"Expected {expected} records but found {count}.")
    return count

def hash_and_upload(path, expected):
    count = create_hash_chain(path, expected)
    # Only replace the data file; the parent directory must already exist.
    run_command(["hdfs", "dfs", "-put", "-f", str(path), HDFS_FILE])
    result = run_command(["hdfs", "dfs", "-stat", "%b", HDFS_FILE],
                         capture_output=True, text=True, timeout=60)
    size = int(result.stdout.strip())
    if size <= 0 or size != path.stat().st_size:
        raise RuntimeError("Uploaded hash-chained file size differs from local output.")
    return count, size, digest_file(path)

def main():
    print("Starting S1 Sqoop ingestion, hash chain and HDFS upload...", flush=True)
    m = Measurement("sqoop", ("sqoop","hash"), "REMOTE_DB_PASSWORD")
    r = m.record
    r.update(hashed_records=0, data_sha256=None, hdfs_file=HDFS_FILE,
             hdfs_upload_size_verified="NOT VERIFIED", hdfs_content_readback="NOT TESTED")
    try:
        m.validate()
        m.start_monitor()
        with tempfile.TemporaryDirectory(prefix="s1_sqoop_") as temporary:
            work = Path(temporary)
            password_file = work / "password"
            password_file.write_text(m.password, encoding="utf-8")
            password_file.chmod(0o400)
            command = ["sqoop", "import", "--connect", REMOTE_DB,
                       "--username", USERNAME, "--password-file", password_file.as_uri(),
                       "--table", m.source, "--target-dir", RAW_HDFS_TARGET, "--delete-target-dir"]
            m.stage("sqoop", lambda: run_command(command))
            hashed = work / "hashed.csv"
            count, size, fingerprint = m.stage("hash", lambda: hash_and_upload(hashed, m.expected))
            r["hashed_records"] = count
            r.update(output_records=count, hdfs_bytes=size, hdfs_storage_mb=size/1_000_000,
                     data_sha256=fingerprint, hdfs_upload_size_verified="PASS")
        r["status"] = "SUCCESS"
    except Exception as exc:
        r["error"] = m.redact(exc)
    finally:
        m.stop_monitor()
    m.finish()
    return m.save_and_show()


if __name__ == "__main__":
    sys.exit(main())
