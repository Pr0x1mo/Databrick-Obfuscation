#!/bin/bash
# finmod-shield setup_secrets.sh
# Run this once on any machine that has the Databricks CLI installed and configured.
# Never commit your actual key to source control.

# Step 1: Install Databricks CLI if not already installed
# pip install databricks-cli

# Step 2: Configure CLI with your workspace and token
# databricks configure --token
# When prompted:
#   host:  https://<your-adb-workspace>.azuredatabricks.net
#   token: <your-personal-access-token>

# Step 3: Generate a 64-char hex key (do this in PowerShell on your machine):
# $secret = ([guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N'))
# Write-Host $secret
# Copy the output. This is your HMAC key. Store it somewhere secure (KeePass, etc).
# Do NOT use your database password as the HMAC key. They must be separate.

# Step 4: Create the secrets scope and store the key
databricks secrets create-scope --scope shield

databricks secrets put \
  --scope shield \
  --key finmod_pseudo_key \
  --string-value "REPLACE_WITH_YOUR_64_CHAR_HEX_KEY"

echo "Done. Verify with: databricks secrets list --scope shield"
