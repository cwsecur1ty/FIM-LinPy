import json
import os
from config import CONFIG_FILE

def load_config():
    """Load FIM configuration from JSON file."""
    default_config = {
        "monitored_paths": [],
        "alert_on_change": True,
        "virustotal_api_key": "",
        "enable_virustotal": False
    }
    
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            # Merge with defaults in case of missing keys
            return {**default_config, **config}
    return default_config

def save_config(config):
    """Save configuration to JSON file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)