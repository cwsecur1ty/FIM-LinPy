#!/bin/bash
# scripts/update_baseline.sh
# Updates baseline checksums

echo "Updating baseline..."
bash "$(dirname "$0")/baseline_gen.sh"
echo "Baseline updated."

# Usage:
# After confirming that changes are legitimate, update your baseline with:
# bash scripts/update_baseline.sh