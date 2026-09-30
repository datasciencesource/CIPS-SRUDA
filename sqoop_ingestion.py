import os
import subprocess
import sys
import time

# =====================================
# S0 - Sqoop Ingestion Configuration
# =====================================

REMOTE_DB = "jdbc:mysql://69.175.69.34/sumrachna_hd"
USERNAME = "sumrachna_hd"
PASSWORD = os.getenv("REMOTE_DB_PASSWORD")

TABLE = "table_stock100"
HDFS_TARGET = "/security_lab/s0"

# =====================================
# Check Credential
# =====================================

if not PASSWORD:
    print("ERROR: REMOTE_DB_PASSWORD is not set.")
    print("Run:")
    print("export REMOTE_DB_PASSWORD='your_password'")
    sys.exit(1)

# =====================================
# Sqoop Import Command
# =====================================

command = [
    "sqoop",
    "import",
    "--connect", REMOTE_DB,
    "--username", USERNAME,
    "--password", PASSWORD,
    "--table", TABLE,
    "--target-dir", HDFS_TARGET,
    "--delete-target-dir"
]

# =====================================
# Experiment Information
# =====================================

print("=" * 60)
print("S0 - SQOOP INGESTION")
print("=" * 60)

print(f"Source table : {TABLE}")
print(f"HDFS target  : {HDFS_TARGET}")
print()

# =====================================
# Execute Sqoop and Measure Time
# =====================================

start_time = time.time()

try:
    result = subprocess.run(command)

    end_time = time.time()
    ingestion_time = end_time - start_time

    # =====================================
    # Result
    # =====================================

    print()
    print("=" * 60)
    print("S0 - INGESTION RESULT")
    print("=" * 60)

    if result.returncode == 0:
        print("Execution status     : SUCCESS")
    else:
        print("Execution status     : FAILED")

    print(
        f"Sqoop ingestion time : "
        f"{ingestion_time:.2f} seconds"
    )

    print("=" * 60)

    sys.exit(result.returncode)

except Exception as error:
    end_time = time.time()
    ingestion_time = end_time - start_time

    print()
    print("=" * 60)
    print("S0 - INGESTION RESULT")
    print("=" * 60)

    print("Execution status     : FAILED")
    print(
        f"Sqoop ingestion time : "
        f"{ingestion_time:.2f} seconds"
    )
    print(f"Error                : {error}")

    print("=" * 60)

    sys.exit(1)
