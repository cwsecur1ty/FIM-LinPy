import os

CONFIG_FILE = "fim_config.json"
BASELINE_FILE = "baseline_checksums.txt"

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-please-change'
    DATABASE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'vuln_scans.db')