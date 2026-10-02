# Databrick-Obfuscation

Deterministic data obfuscation pipeline for the CIBC Finance Modernization platform.

Reads `gold.GLAccount` from Azure SQL (`FinanceModernization`), applies HMAC-SHA256 masking to sensitive columns, writes the masked dataset to a fully separate database (`FinanceModernization_Masked`), and writes an audit-grade original-to-masked lookup table back to the source database.

Built to solve the correct problem: obfuscate in prod first, then move fake data into lower environments. No raw production data ever touches UAT or Dev.

---

## How it works

1. Databricks reads `gold.GLAccount` from `FinanceModernization` via JDBC
2. HMAC-SHA256 masking is applied to sensitive columns via Spark UDFs
3. Masked rows are written to `FinanceModernization_Masked.gold.GLAccount_Masked`
4. Distinct original-to-masked value pairs are written to `FinanceModernization.dbo.ObfuscationMapping` for authorized traceability
5. Validation cell prints original vs masked side by side

## Columns masked

| Column | Type |
|---|---|
| GLACCOUNT | numeric, all digits masked |
| GLACCOUNTEXTERNAL | numeric, all digits masked |
| CORPORATEGROUPACCOUNT | numeric, all digits masked |
| SAMPLEGLACCOUNT | numeric, all digits masked |
| ALTERNATIVEGLACCOUNT | numeric, all digits masked |
| CREATEDBYUSER | alphanumeric, letters and digits masked |

Everything else (flags, chart codes, company codes, dates) is left untouched so the data reads as realistic in context.

## Why HMAC-SHA256

- Deterministic: the same input always produces the same masked output, every run, forever. Referential integrity is preserved across tables and refreshes.
- Format-preserving: leading zeros, length, and character structure are maintained.
- Non-reversible: there is no decrypt path. The only way back to the original value is the `ObfuscationMapping` table, which stays in prod.
- Key-dependent: without the secret key, the masked values are meaningless.

---

## Setup

### 1. Generate your HMAC key (do this once, save it somewhere secure)

```powershell
$secret = ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))
Write-Host $secret
```

### 2. Store your secrets in Databricks (do this once)

Store the HMAC key:

```bash
databricks secrets create-scope --scope shield
databricks secrets put --scope shield --key finmod_pseudo_key --string-value "your-64-char-hex-key"
```

Store your Azure SQL password the same way. The notebook reads both from the shield scope at runtime:

```bash
databricks secrets put --scope shield --key sql_password --string-value "your-sql-password"
```

### 3. Add the Databricks cluster firewall rule in Azure

The Databricks outbound IP must be whitelisted on the Azure SQL server firewall before the notebook can connect.

Portal, SQL Server, Networking, Firewall Rules, add the Databricks NAT IP.

### 4. Import the notebook into Databricks

Workspace, Import, select `glacccount_obfuscation.py`, import as notebook.

### 5. Run cells top to bottom

Cell 3 creates the masked database, gold schema, and lookup table if they do not already exist. Safe to re-run.

---

## Repo structure

```
finmod-shield/
  glacccount_obfuscation.py   # Databricks notebook (import as notebook)
  setup_secrets.sh            # One-time Databricks secrets setup
  requirements.txt            # Python dependencies
  .env.example                # Template for local env vars (never commit real values)
  .gitignore
  README.md
```

---

## Author

Xavier Borja (Proximus) — Senior DBA and Platform Engineer, CIBC Bank USA
GitHub: Pr0x1mo
