from flask import Blueprint, render_template, request, redirect, url_for
from utils.config_handler import load_config, save_config
from scripts.integrity_check import load_baseline, compute_sha256
import os
import time
import pwd
import grp

bp = Blueprint('fim', __name__, url_prefix='/fim')

@bp.route('/')
def index():
    config = load_config()
    monitored_paths = config.get("monitored_paths", [])
    alert_on_change = config.get("alert_on_change", True)

    baseline = load_baseline()
    issues = []

    for file_path, expected_checksum in baseline.items():
        if not os.path.exists(file_path):
            issues.append((file_path, "Missing", "-", "-", "-"))
            continue

        current_checksum = compute_sha256(file_path)
        if current_checksum is None or current_checksum != expected_checksum:
            try:
                file_stat = os.stat(file_path)
                owner = pwd.getpwuid(file_stat.st_uid).pw_name
                group = grp.getgrgid(file_stat.st_gid).gr_name
                last_modified = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_stat.st_mtime))
            except:
                owner, group, last_modified = "-", "-", "-"
            issues.append((file_path, "Modified", owner, group, last_modified))

    return render_template('fim/index.html', 
                         issues=issues, 
                         monitored_paths=monitored_paths, 
                         alert_on_change=alert_on_change)

@bp.route("/approve")
def approve():
    file_path = request.args.get('file')
    if not file_path:
        return "File parameter is missing.", 400
    if not os.path.exists(file_path):
        return f"File {file_path} does not exist.", 404
    
    current_checksum = compute_sha256(file_path)
    if current_checksum is None:
        return f"Could not compute checksum for {file_path}.", 500
    
    baseline = load_baseline()
    baseline[file_path] = current_checksum
    
    try:
        # Get the baseline file path relative to the current file
        baseline_file = os.path.join(os.path.dirname(__file__), '..', 'baseline_checksums.txt')
        with open(baseline_file, 'w') as f:
            for path, checksum in baseline.items():
                f.write(f"{checksum}  {path}\n")
    except Exception as e:
        return f"Error updating baseline: {e}", 500
    
    return redirect(url_for('fim.index'))

@bp.route("/investigate")
def investigate():
    file_path = request.args.get('file')
    if not file_path:
        return "File parameter is missing.", 400
    if not os.path.exists(file_path):
        return f"File {file_path} does not exist.", 404

    baseline = load_baseline()
    baseline_checksum = baseline.get(file_path, "Not Found")
    current_checksum = compute_sha256(file_path)

    try:
        file_stat = os.stat(file_path)
        file_size = file_stat.st_size
        last_modified = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file_stat.st_mtime))
        file_permissions = oct(file_stat.st_mode)[-3:]
        owner = pwd.getpwuid(file_stat.st_uid).pw_name
        group = grp.getgrgid(file_stat.st_gid).gr_name
    except Exception as e:
        return f"Error retrieving file info: {e}", 500

    return render_template('investigation.html',
                         file_path=file_path,
                         baseline_checksum=baseline_checksum,
                         current_checksum=current_checksum,
                         file_size=file_size,
                         last_modified=last_modified,
                         file_permissions=file_permissions,
                         owner=owner,
                         group=group)

@bp.route("/update_config", methods=["POST"])
def update_config():
    config = load_config()
    monitored_paths = config.get("monitored_paths", [])

    if "new_path" in request.form:
        new_path = request.form["new_path"].strip()
        if os.path.exists(new_path) and new_path not in monitored_paths:
            monitored_paths.append(new_path)

    if "remove_path" in request.form:
        remove_path = request.form["remove_path"]
        monitored_paths = [p for p in monitored_paths if p != remove_path]

    config["monitored_paths"] = monitored_paths
    save_config(config)

    return redirect(url_for('fim.index'))

@bp.route("/toggle_alert", methods=["POST"])
def toggle_alert():
    config = load_config()
    config["alert_on_change"] = request.form.get("alert_on_change") == "true"
    save_config(config)
    return redirect(url_for('fim.index'))