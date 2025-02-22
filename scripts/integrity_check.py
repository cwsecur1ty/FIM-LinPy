import hashlib
import os

BASELINE_FILE = os.path.join(os.path.dirname(__file__), '..', 'baseline_checksums.txt')

def compute_sha256(file_path):
    # get checksum for file
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
    # load baseline file 
    baseline = {}
    try:
        with open(baseline_file, "r") as f:
            for line in f:
                # Expecting format -> <checksum>  <filepath>
                parts = line.strip().split("  ", 1)
                if len(parts) == 2:
                    checksum, path = parts
                    baseline[path] = checksum
    except Exception as e:
        print(f"Error grabbing baseline: {e}")
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
        print("File integrity changes found:")
        for file_path, status in issues:
            print(f"{file_path}: {status}")
    else:
        print("All files are intact - no changes found.")

if __name__ == '__main__':
    main()
