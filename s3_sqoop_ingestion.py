import base64
import hashlib
import os
import subprocess
import sys
import threading
import time
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ==========================================================
# S3 - PROTECTED SQOOP INGESTION
# ==========================================================
#
# IMPORTANT:
# /security_lab/s3 is MANUALLY managed.
#
# This script:
#   - DOES NOT create /security_lab/s3
#   - DOES NOT delete /security_lab/s3
#   - CREATES the audit log if it does not exist
#   - APPENDS to the audit log if it already exists
#
# Before a normal run:
#
#   hdfs dfs -rm -r -f /security_lab/s3
#   hdfs dfs -mkdir -p /security_lab/s3
#
# Pipeline:
#
# Remote MySQL
#   -> Sqoop
#   -> /security_lab/s3_staging
#   -> SHA-256 hash-chain generation
#   -> AES-256-GCM encryption
#   -> /security_lab/s3_build/part*
#   -> move encrypted part files only
#   -> /security_lab/s3/part*
#   -> HDFS Data Availability Check
#
# ==========================================================


STRATEGY = "S3"


# ==========================================================
# Remote MySQL Configuration
# ==========================================================

REMOTE_DB = (
    "jdbc:mysql://69.175.69.34/"
    "sumrachna_hd"
)

REMOTE_DB_USER = "sumrachna_hd"

REMOTE_DB_PASSWORD = os.getenv(
    "REMOTE_DB_PASSWORD"
)

SOURCE_TABLE = os.getenv(
    "SOURCE_TABLE"
)


# ==========================================================
# HDFS Paths - S3 ONLY
# ==========================================================

HDFS_STAGING = (
    "/security_lab/s3_staging"
)

HDFS_BUILD = (
    "/security_lab/s3_build"
)

HDFS_TARGET = (
    "/security_lab/s3"
)


# ==========================================================
# Integrity + Confidentiality Configuration
# ==========================================================

HASH_ALGORITHM = "SHA-256"

GENESIS_HASH = "GENESIS"

ENCRYPTION_ALGORITHM = (
    "AES-256-GCM"
)
