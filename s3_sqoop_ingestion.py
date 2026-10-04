print(
    f"Script 1 total measured time          : "
    f"{script1_total_measured_time:.2f} seconds"
)


print()


# ----------------------------------------------------------
# Resource Utilization
# ----------------------------------------------------------

print(
    f"Average CPU utilization               : "
    f"{average_cpu:.2f}%"
)


print(
    f"Peak CPU utilization                  : "
    f"{peak_cpu:.2f}%"
)


print(
    f"Average memory utilization            : "
    f"{average_memory:.2f}%"
)


print(
    f"Peak memory utilization               : "
    f"{peak_memory:.2f}%"
)


print(
    f"HDFS encrypted storage size           : "
    f"{hdfs_size_mb:.4f} MB"
)


print()


# ----------------------------------------------------------
# Security Details
# ----------------------------------------------------------

print(
    f"Hash algorithm                        : "
    f"{HASH_ALGORITHM}"
)


print(
    f"Genesis previous hash                 : "
    f"{GENESIS_HASH}"
)


print(
    f"Final chain hash                      : "
    f"{final_chain_hash}"
)


print(
    f"Encryption algorithm                  : "
    f"{ENCRYPTION_ALGORITHM}"
)


print(
    f"AES key size                          : "
    f"{len(AES_KEY) * 8} bits"
)


print(
    f"Final encrypted dataset               : "
    f"{HDFS_TARGET}/part*"
)


print(
    f"S3 target management                  : "
    f"MANUAL"
)


print(
    f"Audit log                             : "
    f"{AUDIT_LOG}"
)


print(
    "=" * 72
)


# ==========================================================
# Exit
# ==========================================================

sys.exit(
    final_returncode
)
