# PyGuard: Security Monitoring for Linux

PyGuard is a security monitoring platform for Linux systems, providing FIM, vulnerability scanning, account monitoring, and threat-hunting capabilities. Built with Python and Flask - it has command-line tools and a web dashboard (main focus) to help maintain the security of Linux env's.

## Overview

PyGuard combines several functions:

- **File Integrity Monitoring (FIM):** Track changes to system files and detect modifications
- **Vulnerability Scanning:** Identify & track package vulnerabilities
- **Threat Hunting:** Search for IoC's and query VirusTotal (API key can be inserted on config page)
- **Account Monitoring:** Monitor accounts and privilege changes
- **Dashboard:** Get an overview of your system's security & things like CPU load

## Features

### File Integrity Monitoring
- **Baseline Generation:** Create SHA-256 checksums for files
- **Change Detection:** Identify modified, added, or deleted files
- **Investigation:** Investigate changes of files
- **Approvals:** Approve legitimate changes and update your current baselines

### Vulnerability Management
- **Package Scanning:** Check installed packages against known vulnerabilities 
- **Database Integration:** Track scan results over time
- **Bulk Scanning:** Scan all installed packages at once (**routine scanning coming soon**)

### Threat Hunting
- **Hash Search:** Search by hash
- **Path Matching:** Find files by path or query for folder contents
- **VirusTotal Integration:** Validate file hashes against VirusTotal's database
- **Malicious Hash Database:** Maintain a local database of known threats (must be manually added)

### Account Monitoring
- **Account Tracking:** Monitor user accounts and their privileges (need to expand this part)
- **Shell Access:** Track which users have shell access 

## Getting Started

### Prerequisites
- Linux system with Python 3.6+ installed
- pip (Python package manager)
- Git (for cloning the repository)

### Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/PyGuard.git
   cd PyGuard
   ```
2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```
3. **Setup & Launch**
   (In theory the initial launch will set everything up)
   ```bash
   python3 pyguard.py
   ```
4. **Access Dashboard**
   Navigate to: https://127.0.0.1:11010

# Screenshots

# Future Ideas/Work
- Email alerts (smtp)
- Schedule Vuln scans
- More!!!
   
