#!/bin/bash
# scripts/baseline_gen.sh
# Generates baseline checksums using monitored paths from fim_config.json

CONFIG_FILE="../fim_config.json"
BASELINE_FILE="../data/baseline_checksums.txt"

# Read monitored directories from config
MONITOR_DIRS=$(jq -r '.monitored_paths[]' "$CONFIG_FILE")

echo "Generating baseline checksums for monitored directories..."

# Remove existing baseline file if it exists
[ -f "$BASELINE_FILE" ] && rm "$BASELINE_FILE"

# Loop through monitored directories and generate SHA-256 checksums
for dir in $MONITOR_DIRS; do
    if [ -d "$dir" ]; then
        echo "Processing: $dir"
        find "$dir" -type f -exec sha256sum {} \; >> "$BASELINE_FILE"
    else
        echo "Warning: Directory $dir does not exist. Skipping..."
    fi
done

echo "Baseline generated and saved to $BASELINE_FILE"

# Usage:
# Run this script to create (or update) your baseline file:
# bash scripts/baseline_gen.sh
