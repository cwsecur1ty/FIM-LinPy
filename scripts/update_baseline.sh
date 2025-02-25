#!/bin/bash
# scripts/update_baseline.sh
# Updates baseline checksums using the current monitored paths
# The baseline will be saved to data/baseline_checksums.txt

echo "Updating baseline based on current configuration..."
bash "$(dirname "$0")/baseline_gen.sh"
echo "Baseline updated."

# After confirming that changes are legitimate, update your baseline with:
# bash scripts/update_baseline.sh