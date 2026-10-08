"""S3 Script-1: S0 + hash chain + AES-GCM + availability + audit.

Required: REMOTE_DB_PASSWORD, SOURCE_TABLE, S2_AES_KEY_B64.
No authorization token is required. Keep the same AES key for Script-2.
As in S2, a run replaces /security_lab/s3_raw and the final encrypted file.
Hash time includes reading raw HDFS data; encryption time includes upload.
Audit writes are timed separately, outside all processing-stage timers.
S2's ingestion, hashing, encryption/upload order is retained.
HDFS storage is reported in decimal MB (bytes / 1,000,000).
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

REMOTE_DB = "jdbc:mysql://69.175.69.34/sumrachna_hd"
USERNAME = "sumrachna_hd"
RAW_HDFS_TARGET = "/security_lab/s3_raw"
HDFS_TARGET = "/security_lab/s3"
HDFS_FILE = HDFS_TARGET + "/part-00000.enc"
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


def encrypt_and_upload(hash_file, encrypted_file, key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    # Preserves the S2 wire format: nonce(12) + ciphertext + GCM tag(16).
    plaintext = hash_file.read_bytes()
    encrypted_file.write_bytes(nonce + AESGCM(key).encrypt(nonce, plaintext, None))
    # Retain S2's replacement of the strategy output directory.
    run_command(["hdfs", "dfs", "-rm", "-r", "-f", HDFS_TARGET])
    run_command(["hdfs", "dfs", "-mkdir", "-p", HDFS_TARGET])
    run_command(["hdfs", "dfs", "-put", "-f", str(encrypted_file), HDFS_FILE])


def check_hdfs_availability(encrypted_file, downloaded_file):
    # Check the actual dataset, not just the NameNode or directory.
    run_command(["hdfs", "dfs", "-test", "-s", HDFS_FILE], timeout=60)
    run_command(["hdfs", "dfs", "-get", HDFS_FILE, str(downloaded_file)], timeout=300)
    size = downloaded_file.stat().st_size
    fingerprint = digest_file(downloaded_file)
    if size != encrypted_file.stat().st_size or fingerprint != digest_file(encrypted_file):
        raise RuntimeError("S3 HDFS dataset differs from the encrypted output; workflow blocked.")
    return size, fingerprint



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
        ("Total pipeline time", "Current", "seconds", "PENDING - completed by matching PySpark run"),
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
                 "HDFS availability checked and audit events recorded.")
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

def main():
    os.umask(0o077)
    source_table = os.getenv("SOURCE_TABLE", "")
    scale, expected = DATASETS.get(source_table, ("UNKNOWN", None))
    password = os.getenv("REMOTE_DB_PASSWORD", "")
    key_text = os.getenv("S2_AES_KEY_B64", "")
    run_id = uuid.uuid4().hex
    audit_path = Path(os.getenv("S3_AUDIT_LOG", "/tmp/s3_audit.log"))
    results_dir = Path(os.getenv("S3_RESULTS_DIR", "/tmp/s3_results"))
    timings = {name: 0.0 for name in ("sqoop", "hash", "encryption", "hdfs_availability", "audit_logging")}
    stages = {name: "NOT RUN" for name in ("sqoop", "hash", "encryption", "hdfs_availability")}
    audit_status = "NOT RUN"
    status, error = "FAILED", "N/A"
    records, storage_bytes = 0, None
    ciphertext_sha256 = None
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
            entry = dict(timestamp=now(), run_id=run_id, strategy="S3", script="sqoop",
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
            raise ValueError("Set REMOTE_DB_PASSWORD and a valid SOURCE_TABLE.")
        try:
            key = base64.b64decode(key_text, validate=True)
            if len(key) != 32:
                raise ValueError
        except Exception:
            raise ValueError("S2_AES_KEY_B64 must decode to exactly 32 bytes.") from None
        with tempfile.TemporaryDirectory(prefix="s3_sqoop_") as temporary:
            work = Path(temporary)
            password_file = work / "password"
            password_file.write_text(password, encoding="utf-8")
            password_file.chmod(0o400)
            command = ["sqoop", "import", "--connect", REMOTE_DB,
                       "--username", USERNAME, "--password-file", password_file.as_uri(),
                       "--table", source_table, "--target-dir", RAW_HDFS_TARGET,
                       "--delete-target-dir"]
            stage("sqoop", lambda: run_command(command))
            hash_file, encrypted_file = work / "hashed.csv", work / "data.enc"
            records = stage("hash", lambda: create_hash_chain(hash_file, expected))
            stage("encryption", lambda: encrypt_and_upload(hash_file, encrypted_file, key))
            storage_bytes, ciphertext_sha256 = stage("hdfs_availability", lambda: check_hdfs_availability(
                encrypted_file, work / "readback.enc"))
        audit("WORKFLOW_COMPLETED", "PASS", "Script-1 complete; ALLOW handoff to Script-2.", records=records)
        status = "SUCCESS"
    except Exception as exc:
        error = redact(exc)
        try:
            audit("WORKFLOW_COMPLETED", "FAIL", error, decision="BLOCK", stage_status=stages)
        except Exception as audit_exc:
            error += "; " + str(audit_exc)
    finally:
        monitor.stop.set()
        monitor.thread.join()

    end_label = now()
    wall_time = time.perf_counter() - workflow_start
    s0 = timings["sqoop"]
    s1 = s0 + timings["hash"]
    s2 = s1 + timings["encryption"]
    s3 = s2 + timings["hdfs_availability"] + timings["audit_logging"]

    def mean(values):
        return sum(values) / len(values) if values else None

    metrics = dict(
        run_id=run_id, strategy="S3", script="sqoop", dataset=scale,
        source_table=source_table, expected_records=expected, output_records=records,
        start=start_label, end=end_label, status=status, error=error,
        component_seconds=timings,
        cumulative_seconds={"S0-Script-1": s0, "S1-Script-1": s1, "S2-Script-1": s2, "S3-Script-1": s3},
        script_wall_seconds=wall_time, stage_status=stages, audit_status=audit_status,
        hdfs_file=HDFS_FILE, hdfs_bytes=storage_bytes, ciphertext_sha256=ciphertext_sha256,
        measurement_schema_version=2,
        hdfs_storage_mb=storage_bytes / 1_000_000 if storage_bytes is not None else None,
        throughput_records_per_second=records / s3 if status == "SUCCESS" and s3 else None,
        cpu_average_percent=mean(monitor.cpu), cpu_peak_percent=max(monitor.cpu, default=None),
        memory_average_percent=mean(monitor.memory), memory_peak_percent=max(monitor.memory, default=None),
        resource_scope="whole host/VM", monitoring_error=monitor.error,
        monitoring_window="ingestion through encryption/upload, availability check and workflow completion",
        cpu_sample_count=len(monitor.cpu), memory_sample_count=len(monitor.memory),
        cpu_sample_sum=sum(monitor.cpu), memory_sample_sum=sum(monitor.memory),
        retries=0, pipeline_total_seconds=None,
        timing_note="Hash includes HDFS read; encryption includes HDFS upload. Audit timers do not overlap stage timers. Summary saving is excluded. Cumulative values are components of this run, not separate S0-S2 experiments.",
    )
    result_path = results_dir / ("s3_sqoop_" + run_id + ".json")
    save_error = None
    try:
        results_dir.mkdir(parents=True, exist_ok=True)
        with result_path.open("x", encoding="utf-8") as output:
            json.dump(metrics, output, indent=2)
            output.write("\n")
    except Exception as exc:
        save_error = redact(exc)

    def show(label, value):
        print(f"{label:<39}: {value}")

    print("=" * 76)
    print("S3 - CUMULATIVE SQOOP RESULT")
    print("=" * 76)
    for label, value in [("Run ID", run_id), ("Laboratory environment", "S3"),
                         ("Strategy under test", "S3"),
                         ("Dataset scale", scale), ("Source table", source_table),
                         ("Workflow start time", start_label), ("Workflow end time", end_label),
                         ("Execution status", status)]:
        show(label, value)
    for label, value in [("S0-Script-1 time", s0), ("Hash-chain time", timings["hash"]),
                         ("S1-Script-1 total time", s1), ("AES-GCM encryption + upload time", timings["encryption"]),
                         ("S2-Script-1 total time", s2), ("HDFS availability-check time", timings["hdfs_availability"]),
                         ("Audit-logging time", timings["audit_logging"]),
                         ("S3-Script-1 total time", s3), ("Script wall-clock time", wall_time)]:
        show(label, f"{value:.6f} seconds")
    for name, value in stages.items():
        show(name.replace("_", " ").title() + " status", value)
    show("Audit logging", audit_status)
    show("S0 baseline workflow", "RETAINED")
    show("S1 hash-chain generation", stages["hash"])
    show("S2 AES-GCM encryption", stages["encryption"])
    show("S3 HDFS availability check", stages["hdfs_availability"])
    show("HDFS output verified", stages["hdfs_availability"])
    show("HDFS storage size (MB)", f"{storage_bytes / 1_000_000:.6f}" if storage_bytes is not None else "N/A")
    show("Output records", records)
    show("Expected records", expected)
    rate = metrics["throughput_records_per_second"]
    show("Script-1 throughput (records/second)", f"{rate:.4f}" if rate is not None else "N/A")
    for label, field in [("Average CPU utilization", "cpu_average_percent"), ("Peak CPU utilization", "cpu_peak_percent"),
                         ("Average memory utilization", "memory_average_percent"), ("Peak memory utilization", "memory_peak_percent")]:
        value = metrics[field]
        show(label, f"{value:.2f}%" if value is not None else "N/A")
    show("Resource measurement scope", "Whole host/VM")
    show("Monitoring error", monitor.error or "N/A")
    show("Script-1 handoff decision", "ALLOW" if status == "SUCCESS" and not save_error else "BLOCK")
    show("Number of script retries", 0)
    show("Retry scope", "Automatic retries only; record manual reruns separately")
    show("Abnormal condition observed", "YES" if status != "SUCCESS" or save_error or monitor.error else "NO")
    show("Error / failure message", error)
    show("Audit log file", audit_path)
    show("Measurement record", result_path if not save_error else "SAVE FAILED: " + save_error)
    show("Total pipeline time", "PENDING - run PySpark next for combined results")
    print("=" * 76)
    print("SAVED JSON RESULT" if not save_error else "JSON RESULT - FILE SAVE FAILED")
    if not save_error:
        print(f"File: {result_path}")
    print(json.dumps(metrics, indent=2))
    print("=" * 76)
    print_instrument_tables(metrics, save_error)
    return 0 if status == "SUCCESS" and not save_error else 1


if __name__ == "__main__":
    sys.exit(main())
