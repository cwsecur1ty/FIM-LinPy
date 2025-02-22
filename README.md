# FIM-LinPy: File Integrity Monitoring for Linux

FIM-LinPy is a lightweight tool for monitoring the integrity of critical files on Linux systems. A combination of Bash and Python is used to generate a baseline of file checksums and then verify that files have not been modified or tampered with.

## Overview

- **Baseline Generation:**  
  The Bash script (`scripts/baseline_gen.sh`) scans a target directory (e.g., `/etc`) and creates a baseline file (`baseline_checksums.txt`) with SHA-256 checksums for all files.

- **Integrity Check:**  
  The Python script (`scripts/integrity_check.py`) reads the baseline file, recalculates current file checksums, and reports any discrepancies (e.g., missing or modified files).

- **Baseline Update:**  
  The optional Bash script (`scripts/update_baseline.sh`) allows you to update your baseline after you verify that changes are legitimate. 

## Features

- **Automated Baseline Generation:** Quickly generate a secure snapshot of your system's state.
- **Periodic Integrity Checks:** Verify that your system files remain unaltered.
- **Easy Integration:** Combine with cron or other scheduling tools for regular monitoring.
- **Customisable:** Modify target directories, checksum algorithms, and more.

## Getting Started

## Example Usage
![image](https://github.com/user-attachments/assets/0a575944-2fe8-4beb-9677-9103a5b2930b)

### Prerequisites

- Linux system with Bash and Python 3 installed.
- Basic familiarity with the Linux command line.

### Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/FIM-LinPy.git
   cd FIM-LinPy
   ```
2. **Permissions:**

   ```bash
   chmod +x scripts/*.sh
   chmod +x scripts/integrity_check.py
   ```
## Usage

Run the baseline generation script to create the initial checksum baseline (baseline_checksums.txt):
  ```bash
  sudo bash scripts/baseline_gen.sh
  ```

Check initial file integrity:
  ```bash
  sudo python3 scripts/integrity_check.py
  ```
This will generate a report based on any identifiable changes.

To update the baseline:
  ```bash
  sudo bash scripts/update_baseline.sh
  ```

# Automation

Schedule the integrity check using a cron job to run at regular intervals, changing the intervals based on requirements.
  ```bash
  0 0 * * * /usr/bin/env python3 /path/to/FIM-LinPy/scripts/integrity_check.py
  # Will run every day at midnight
  ```

# Future Additions
- I plan to add to the script to add alerts (via email &or messaging).
- Configuration file to make it easier to adjust settings (target directory, baseline file location etc)




