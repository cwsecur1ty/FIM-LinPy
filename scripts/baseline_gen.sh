#!/bin/bash
# scripts/baseline_gen.sh
# Generates baseline checksums

# Adjust these variables as required
MONITOR_DIR="/etc"
# Save the baseline file in the project root directory
BASELINE_FILE="../baseline_checksums.txt"

echo "Generating baseline checksums for $MONITOR_DIR..."

# Remove any existing baseline file
[ -f "$BASELINE_FILE" ] && rm "$BASELINE_FILE"

# Find all files under $MONITOR_DIR and get SHA-256 checksums
find "$MONITOR_DIR" -type f -exec sha256sum {} \; > "$BASELINE_FILE"

echo "Baseline generated and saved to $BASELINE_FILE"

# Usage:
# Run this script to create (or update) your baseline file:
# bash scripts/baseline_gen.sh

