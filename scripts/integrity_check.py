import hashlib
import os
import json

# Configuration and baseline file locations
CONFIG_FILE = os.path.join(os.path.dirname(__file__), '..', 'fim_config.json')
BASELINE_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'baseline_checksums.txt')

def load_config():
    """Load monitored paths from JSON config file."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                return config.get("monitored_paths", [])
        except Exception as e:
            print(f"Error loading config file: {e}")
            return []
    return []

def compute_sha256(file_path):
    """Compute the SHA-256 checksum for the given file."""
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
    """Load baseline file checksums."""
    baseline = {}
    try:
        with open(baseline_file, "r") as f:
            for line in f:
                parts = line.strip().split("  ", 1)
                if len(parts) == 2:
                    checksum, path = parts
                    baseline[path] = checksum
    except Exception as e:
        print(f"Error loading baseline file: {e}")
    return baseline

def verify_integrity(baseline):
    """
    Compare current file checksums against the baseline.
    Returns a list of tuples: (file_path, status) for issues found.
    """
    compromised = []
    monitored_paths = load_config()

    for monitored_path in monitored_paths:
        for root, _, files in os.walk(monitored_path):
            for file in files:
                file_path = os.path.join(root, file)
                expected_checksum = baseline.get(file_path)
                if expected_checksum is None:
                    compromised.append((file_path, "New File"))
                    continue
                current_checksum = compute_sha256(file_path)
                if current_checksum is None or current_checksum != expected_checksum:
                    compromised.append((file_path, "Modified"))

    # Also check for missing files that were in the baseline but are now gone
    for file_path in baseline.keys():
        if not os.path.exists(file_path):
            compromised.append((file_path, "Missing"))

    return compromised

def main():
    baseline = load_baseline()
    issues = verify_integrity(baseline)
    if issues:
        print("File integrity changes found:")
        for file_path, status in issues:
            print(f"{file_path}: {status}")
    else:
        print("All monitored files are intact - no changes found.")

if __name__ == '__main__':
    main()
