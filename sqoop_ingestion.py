import subprocess
import time

# =====================================
# S0 - Sqoop Ingestion Configuration
# =====================================

REMOTE_DB = "jdbc:mysql://69.175.69.34/sumrachna_hd"
USERNAME = "sumrachna_hd"
PASSWORD = "RootAdmin11!!"
TABLE = "table_stock100"
HDFS_TARGET = "/security_lab/s0"

# =====================================
# Sqoop Import
# =====================================

command = [
    "sqoop", "import",
    "--connect", REMOTE_DB,
    "--username", USERNAME,
    "--password", PASSWORD,
    "--table", TABLE,
    "--target-dir", HDFS_TARGET,
    "--delete-target-dir"
]

print("Starting Sqoop ingestion...")
print(f"Source table: {TABLE}")
print(f"HDFS target: {HDFS_TARGET}")

start_time = time.time()

result = subprocess.run(command)

end_time = time.time()

ingestion_time = end_time - start_time

# =====================================
# Result
# =====================================

if result.returncode == 0:
    print("Sqoop ingestion: SUCCESS")
else:
    print("Sqoop ingestion: FAILED")

print(f"Ingestion time: {ingestion_time:.2f} seconds")
