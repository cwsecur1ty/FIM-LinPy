from flask import Blueprint, render_template, current_app
from scripts.integrity_check import load_baseline, compute_sha256
from scripts.user_accounts import get_user_accounts
from scripts.system_stats import get_system_stats
from scripts.db_helpers import get_all_scans
import time
import os
from functools import lru_cache
from datetime import datetime, timedelta

bp = Blueprint('dashboard', __name__)

# Cache system stats for 5 seconds
@lru_cache(maxsize=1)
def get_cached_system_stats():
    return get_system_stats()

# Cache baseline data for 30 seconds
@lru_cache(maxsize=1)
def get_cached_baseline():
    return load_baseline()

@bp.route('/')
def index():
    # Get FIM statistics efficiently
    baseline = get_cached_baseline()
    modified_files = 0
    
    # Process files in batches
    batch_size = 100
    for i in range(0, len(baseline), batch_size):
        batch = list(baseline.items())[i:i + batch_size]
        for file_path, expected_checksum in batch:
            if not os.path.exists(file_path) or compute_sha256(file_path) != expected_checksum:
                modified_files += 1

    fim_stats = {
        'total_files': len(baseline),
        'modified_files': modified_files
    }

    # Get user account statistics
    accounts = get_user_accounts()
    account_stats = {
        'total_users': len(accounts)
    }

    # Get vulnerability statistics efficiently
    packages = get_all_scans()
    vulnerable_count = sum(1 for pkg in packages if pkg.get('vulns'))
    vuln_stats = {
        'total_packages': len(packages),
        'vulnerable_packages': vulnerable_count
    }

    # Get cached system statistics
    system_stats = get_cached_system_stats()

    # Get recent activity more efficiently
    recent_activity = get_recent_activity(baseline, packages)

    return render_template('dashboard/index.html',
                         fim_stats=fim_stats,
                         account_stats=account_stats,
                         vuln_stats=vuln_stats,
                         system_stats=system_stats,
                         recent_activity=recent_activity)

def get_recent_activity(baseline, packages, limit=10):
    """Get recent activity more efficiently"""
    activity = []
    
    # Add only the most recent file modifications
    for file_path, expected_checksum in baseline.items():
        if not os.path.exists(file_path):
            activity.append({
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'title': 'File Missing',
                'description': f'File not found: {file_path}',
                'timestamp': datetime.now()  # For sorting
            })
            continue
        
        current_checksum = compute_sha256(file_path)
        if current_checksum != expected_checksum:
            activity.append({
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'title': 'File Modified',
                'description': f'Changes detected in: {file_path}',
                'timestamp': datetime.now()
            })

    # Add only recent vulnerable packages
    for pkg in packages:
        if pkg.get('vulns') and pkg.get('last_scanned'):
            activity.append({
                'time': pkg['last_scanned'],
                'title': 'Vulnerability Detected',
                'description': f'Package {pkg["package"]} has {len(pkg["vulns"])} vulnerabilities',
                'timestamp': datetime.strptime(pkg['last_scanned'], '%Y-%m-%d %H:%M:%S')
            })

    # Sort by timestamp and limit efficiently
    activity.sort(key=lambda x: x['timestamp'], reverse=True)
    return activity[:limit]