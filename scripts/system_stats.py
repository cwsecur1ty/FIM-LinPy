import psutil
import time
from datetime import datetime, timedelta

def get_system_stats():
    """Get basic system statistics"""
    try:
        # Get CPU and memory info
        cpu_load = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        memory_usage = memory.percent
        
        # Get uptime
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        uptime_str = format_uptime(uptime)

        return {
            'cpu_load': round(cpu_load, 1),
            'memory_usage': round(memory_usage, 1),
            'uptime': uptime_str
        }
    except Exception as e:
        print(f"Error getting system stats: {e}")
        return {
            'cpu_load': 0,
            'memory_usage': 0,
            'uptime': 'Unknown'
        }

def format_uptime(uptime):
    """Format timedelta into readable string"""
    days = uptime.days
    hours = uptime.seconds // 3600
    minutes = (uptime.seconds % 3600) // 60
    
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"