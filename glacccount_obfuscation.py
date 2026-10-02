# Databricks notebook source
# Author: Xavier Borja (Proximus) — Senior DBA and Platform Engineer, CIBC Bank USA
# Description: Reads gold.GLAccount from Azure SQL (FinanceModernization),
#              applies deterministic HMAC-SHA256 masking to sensitive columns,
#              writes masked output to FinanceModernization_Masked.gold.GLAccount_Masked,
#              and writes original->masked lookup to FinanceModernization.dbo.ObfuscationMapping

# COMMAND ----------

# CELL 1 - INSTALL DEPENDENCIES
# Uncomment and run this cell first on a fresh cluster

# %pip install faker pyodbc

# COMMAND ----------

# CELL 2 - IMPORTS AND CONFIG

import hmac
import hashlib
import re
from datetime import datetime
from pyspark.sql import functions as F
from pyspark.sql.types import StringType
from faker import Faker
import pyodbc

fake = Faker()
Faker.seed(0)

SOURCE_JDBC_URL = (
    "jdbc:sqlserver://jmplabsv04.database.windows.net:1433;"
    "database=FinanceModernization;"
    "encrypt=true;"
    "trustServerCertificate=false;"
    "hostNameInCertificate=*.database.windows.net;"
    "loginTimeout=30;"
)

TARGET_JDBC_URL = (
    "jdbc:sqlserver://jmplabsv04.database.windows.net:1433;"
    "database=FinanceModernization_Masked;"
    "encrypt=true;"
    "trustServerCertificate=false;"
    "hostNameInCertificate=*.database.windows.net;"
    "loginTimeout=30;"
)

JDBC_PROPS = {
    "user": "Proximus",
    "password": dbutils.secrets.get(scope="shield", key="sql_password"),
    "driver": "com.microsoft.sqlserver.jdbc.SQLServerDriver"
}

SOURCE_TABLE = "gold.GLAccount"
TARGET_TABLE = "gold.GLAccount_Masked"
LOOKUP_TABLE = "dbo.ObfuscationMapping"

# COMMAND ----------

# CELL 3 - CREATE MASKED DATABASE, GOLD SCHEMA, AND LOOKUP TABLE
# pyodbc handles DDL that JDBC cannot run (CREATE DATABASE)

print("Setting up databases and schemas...")

conn_str_master = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=jmplabsv04.database.windows.net,1433;"
    "DATABASE=master;"
    "UID=Proximus;"
    f"PWD={dbutils.secrets.get(scope='shield', key='sql_password')};"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
)

conn_str_masked = conn_str_master.replace("DATABASE=master;", "DATABASE=FinanceModernization_Masked;")
conn_str_source = conn_str_master.replace("DATABASE=master;", "DATABASE=FinanceModernization;")

try:
    conn = pyodbc.connect(conn_str_master, autocommit=True)
    cursor = conn.cursor()
    cursor.execute("""
        IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = 'FinanceModernization_Masked')
            CREATE DATABASE [FinanceModernization_Masked]
    """)
    print("  FinanceModernization_Masked exists or was created")
    cursor.close()
    conn.close()
except Exception as e:
    print(f"  Failed to create masked database: {e}")
    raise

try:
    conn = pyodbc.connect(conn_str_masked, autocommit=True)
    cursor = conn.cursor()
    cursor.execute("""
        IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = 'gold')
            EXEC('CREATE SCHEMA gold')
    """)
    print("  gold schema exists or was created in FinanceModernization_Masked")
    cursor.close()
    conn.close()
except Exception as e:
    print(f"  Failed to create gold schema: {e}")
    raise

try:
    conn = pyodbc.connect(conn_str_source, autocommit=True)
    cursor = conn.cursor()
    cursor.execute("""
        IF NOT EXISTS (
            SELECT 1 FROM sys.tables t
            JOIN sys.schemas s ON t.schema_id = s.schema_id
            WHERE s.name = 'dbo' AND t.name = 'ObfuscationMapping'
        )
        CREATE TABLE dbo.ObfuscationMapping (
            MappingID     BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
            TableName     NVARCHAR(255) NOT NULL,
            ColumnName    NVARCHAR(255) NOT NULL,
            OriginalValue NVARCHAR(500) NULL,
            MaskedValue   NVARCHAR(500) NULL,
            CreatedAt     DATETIME NOT NULL DEFAULT GETDATE()
        )
    """)
    print("  ObfuscationMapping table exists or was created in FinanceModernization")
    cursor.close()
    conn.close()
except Exception as e:
    print(f"  Failed to create lookup table: {e}")
    raise

# COMMAND ----------

# CELL 4 - HMAC KEY + CORE FUNCTIONS

# in cmd run this once to store the key:
# databricks secrets create-scope --scope shield
# databricks secrets put --scope shield --key finmod_pseudo_key --string-value "your64hexkey"

PSEUDO_KEY = dbutils.secrets.get(scope="shield", key="finmod_pseudo_key")


def _pseudo_digit_stream(key: bytes, seed: str, n: int) -> list:
    out, i = [], 0
    while len(out) < n:
        block = hmac.new(key, f"{seed}|{i}".encode("utf-8"), hashlib.sha256).digest()
        out.extend(b % 10 for b in block)
        i += 1
    return out[:n]


def deterministic_numeric_like(value: str, preserve_last: int = 0, key: str = PSEUDO_KEY) -> str:
    """
    Mask a numeric string deterministically.
    Same input always produces the same masked output.
    Preserves format including leading zeros.
    """
    if value is None:
        return value
    s = str(value).strip()
    digits = re.sub(r"\D", "", s)
    if not digits:
        return s
    keep = digits[-preserve_last:] if 0 < preserve_last < len(digits) else ""
    repl_len = len(digits) - len(keep)
    stream = _pseudo_digit_stream(key.encode("utf-8"), digits, repl_len)
    new_digits = "".join(str(d) for d in stream) + keep
    result, idx = [], 0
    for ch in s:
        if ch.isdigit():
            result.append(new_digits[idx])
            idx += 1
        else:
            result.append(ch)
    return "".join(result)


def deterministic_alpha_numeric(value: str, key: str = PSEUDO_KEY) -> str:
    """
    Mask alphanumeric strings deterministically.
    Letters stay letters, digits stay digits, format preserved.
    Used for CREATEDBYUSER (e.g. JSMITH01 -> KBROWN04)
    """
    if value is None:
        return value
    s = str(value).strip()
    key_bytes = key.encode("utf-8")
    block = hmac.new(key_bytes, s.encode("utf-8"), hashlib.sha256).digest()
    LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = []
    byte_idx = 0
    for ch in s:
        if ch.isalpha():
            result.append(LETTERS[block[byte_idx % 32] % 26])
            byte_idx += 1
        elif ch.isdigit():
            result.append(str(block[byte_idx % 32] % 10))
            byte_idx += 1
        else:
            result.append(ch)
    return "".join(result)

# COMMAND ----------

# CELL 5 - REGISTER SPARK UDFs

mask_numeric_udf  = F.udf(lambda v: deterministic_numeric_like(v) if v else v, StringType())
mask_alphanum_udf = F.udf(lambda v: deterministic_alpha_numeric(v) if v else v, StringType())

# COMMAND ----------

# CELL 6 - READ SOURCE TABLE

print(f"\nReading {SOURCE_TABLE} from FinanceModernization...")

df = spark.read.jdbc(url=SOURCE_JDBC_URL, table=SOURCE_TABLE, properties=JDBC_PROPS)

row_count = df.count()
print(f"  {row_count} rows loaded")
df.printSchema()
df.show(5, truncate=True)

# COMMAND ----------

# CELL 7 - APPLY OBFUSCATION
# Columns masked:
#   GLACCOUNT               GL account number         -> mask all digits
#   GLACCOUNTEXTERNAL       external account number   -> mask all digits
#   CORPORATEGROUPACCOUNT   corporate group account   -> mask all digits
#   SAMPLEGLACCOUNT         sample GL account ref     -> mask all digits
#   ALTERNATIVEGLACCOUNT    alternative GL account    -> mask all digits
#   CREATEDBYUSER           SAP user ID               -> mask alphanumeric
#
# Everything else is non-PII and left untouched.

print("\nApplying HMAC-SHA256 obfuscation...")

df_masked = df \
    .withColumn("GLACCOUNT",             mask_numeric_udf(F.col("GLACCOUNT"))) \
    .withColumn("GLACCOUNTEXTERNAL",     mask_numeric_udf(F.col("GLACCOUNTEXTERNAL"))) \
    .withColumn("CORPORATEGROUPACCOUNT", mask_numeric_udf(F.col("CORPORATEGROUPACCOUNT"))) \
    .withColumn("SAMPLEGLACCOUNT",       mask_numeric_udf(F.col("SAMPLEGLACCOUNT"))) \
    .withColumn("ALTERNATIVEGLACCOUNT",  mask_numeric_udf(F.col("ALTERNATIVEGLACCOUNT"))) \
    .withColumn("CREATEDBYUSER",         mask_alphanum_udf(F.col("CREATEDBYUSER")))

print("  Obfuscation applied. Preview:")
df_masked.select(
    "GLAccountKey", "GLACCOUNT", "GLACCOUNTEXTERNAL", "CORPORATEGROUPACCOUNT", "CREATEDBYUSER"
).show(10, truncate=False)

# COMMAND ----------

# CELL 8 - WRITE MASKED DATA TO FinanceModernization_Masked

print(f"\nWriting masked data to FinanceModernization_Masked.{TARGET_TABLE}...")

df_masked.write.jdbc(
    url=TARGET_JDBC_URL,
    table=TARGET_TABLE,
    mode="overwrite",
    properties=JDBC_PROPS
)

print(f"  Done. {row_count} rows written to FinanceModernization_Masked.{TARGET_TABLE}")

# COMMAND ----------

# CELL 9 - WRITE LOOKUP MAPPINGS TO FinanceModernization.dbo.ObfuscationMapping

print(f"\nWriting lookup mappings to FinanceModernization.{LOOKUP_TABLE}...")

MASKED_COLUMNS = [
    ("GLACCOUNT",             mask_numeric_udf),
    ("GLACCOUNTEXTERNAL",     mask_numeric_udf),
    ("CORPORATEGROUPACCOUNT", mask_numeric_udf),
    ("SAMPLEGLACCOUNT",       mask_numeric_udf),
    ("ALTERNATIVEGLACCOUNT",  mask_numeric_udf),
    ("CREATEDBYUSER",         mask_alphanum_udf),
]

run_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

for col_name, mask_udf in MASKED_COLUMNS:
    print(f"  Processing lookup for {col_name}...")

    df_lookup = df.select(F.col(col_name).alias("OriginalValue")) \
        .filter(F.col(col_name).isNotNull()) \
        .distinct() \
        .withColumn("TableName",   F.lit("gold.GLAccount")) \
        .withColumn("ColumnName",  F.lit(col_name)) \
        .withColumn("MaskedValue", mask_udf(F.col("OriginalValue"))) \
        .withColumn("CreatedAt",   F.lit(run_time)) \
        .select("TableName", "ColumnName", "OriginalValue", "MaskedValue", "CreatedAt")

    mapping_count = df_lookup.count()

    df_lookup.write.jdbc(
        url=SOURCE_JDBC_URL,
        table=LOOKUP_TABLE,
        mode="append",
        properties=JDBC_PROPS
    )

    print(f"    {mapping_count} distinct mappings written for {col_name}")

print(f"\n  All lookup mappings written to FinanceModernization.{LOOKUP_TABLE}")

# COMMAND ----------

# CELL 10 - VALIDATION

print("\n" + "=" * 60)
print("VALIDATION - Original vs Masked")
print("=" * 60)

df_original = spark.read \
    .jdbc(url=SOURCE_JDBC_URL, table=SOURCE_TABLE, properties=JDBC_PROPS) \
    .select("GLAccountKey", "GLACCOUNT", "GLACCOUNTEXTERNAL", "CREATEDBYUSER") \
    .limit(10)

df_masked_check = spark.read \
    .jdbc(url=TARGET_JDBC_URL, table=TARGET_TABLE, properties=JDBC_PROPS) \
    .select("GLAccountKey", "GLACCOUNT", "GLACCOUNTEXTERNAL", "CREATEDBYUSER") \
    .limit(10)

print("\nORIGINAL (FinanceModernization.gold.GLAccount):")
df_original.show(truncate=False)

print("MASKED (FinanceModernization_Masked.gold.GLAccount_Masked):")
df_masked_check.show(truncate=False)

print("\nLOOKUP TABLE SAMPLE (FinanceModernization.dbo.ObfuscationMapping):")
spark.read \
    .jdbc(url=SOURCE_JDBC_URL, table=LOOKUP_TABLE, properties=JDBC_PROPS) \
    .limit(10) \
    .show(truncate=False)

print("\nObfuscation pipeline complete.")
print(f"  Source:  FinanceModernization.gold.GLAccount              ({row_count} rows)")
print(f"  Masked:  FinanceModernization_Masked.gold.GLAccount_Masked")
print(f"  Lookup:  FinanceModernization.dbo.ObfuscationMapping")
print("")
print("  ( *_*)")
print("  ( *_*)>+-+-+")
print("  (+-+_+-)  data? never heard of her.")
