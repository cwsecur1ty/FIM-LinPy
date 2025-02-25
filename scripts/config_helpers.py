import json
import os

CONFIG_FILE = "fim_config.json"

def load_config():
    """Load FIM configuration from JSON file."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {"monitored_paths": [], "alert_on_change": True}
