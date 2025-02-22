#!/usr/bin/env python3
# scripts/integrity_check.py
import hashlib
import os

# Define the path to the baseline file
# (Assumes baseline_checksums.txt is in the project root)
BASELINE_FILE = os.path.join(os.path.dirname(__file__), '..', 'baseline_checksums.txt')

def compute_sha256(file_path):
    """
    Compute the SHA-256 checksum for the given file.
    """
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None
    return hash_sha256.hexdigest()

def load_baseline(baseline_file=BASELINE_FILE):
    """
    Load the baseline file into a dictionary mapping file paths to checksums.
    """
    baseline = {}
    try:
        with open(baseline_file, "r") as f:
            for line in f:
                # Expecting lines in the format: <checksum>  <filepath>
                parts = line.strip().split("  ", 1)
                if len(parts) == 2:
                    checksum, path = parts
                    baseline[path] = checksum
    except Exception as e:
        print(f"Error loading baseline: {e}")
    return baseline

def verify_integrity(baseline):
    """
    Compare current file checksums against the baseline.
    Returns a list of tuples: (file_path, status) for issues found.
    """
    compromised = []
    for file_path, expected_checksum in baseline.items():
        if not os.path.exists(file_path):
            compromised.append((file_path, "Missing"))
            continue
        current_checksum = compute_sha256(file_path)
        if current_checksum is None or current_checksum != expected_checksum:
            compromised.append((file_path, "Modified"))
    return compromised

def main():
    baseline = load_baseline()
    issues = verify_integrity(baseline)
    if issues:
        print("Integrity issues found:")
        for file_path, status in issues:
            print(f"{file_path}: {status}")
    else:
        print("All files are intact.")

if __name__ == '__main__':
    main()
