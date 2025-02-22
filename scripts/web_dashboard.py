# scripts/web_dashboard.py

from flask import Flask, render_template_string, request, redirect
import os, time
from integrity_check import load_baseline, verify_integrity, compute_sha256

app = Flask(__name__)

# Dashboard
dashboard_template = """
<!doctype html>
<html>
<head>
    <title>FIM-LinPy Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; }
        table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .container { max-width: 800px; margin: 0 auto; }
        a.button { 
            display: inline-block; 
            padding: 10px 15px; 
            background: #007BFF; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px; 
            margin-top: 20px;
        }
        a.approve-button {
            padding: 5px 10px;
            background: #28a745;
            color: white;
            text-decoration: none;
            border-radius: 3px;
        }
        a.investigate-button {
            padding: 5px 10px;
            background: #dc3545;
            color: white;
            text-decoration: none;
            border-radius: 3px;
            margin-left: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>FIM-LinPy Dashboard</h1>
        <p>File integrity check results:</p>
        {% if issues %}
            <table>
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {% for file_path, status in issues %}
                    <tr>
                        <td>{{ file_path }}</td>
                        <td>{{ status }}</td>
                        <td>
                            {% if status == 'Modified' %}
                                <a href="/approve?file={{ file_path | urlencode }}" class="approve-button">Approve Change</a>
                                <a href="/investigate?file={{ file_path | urlencode }}" class="investigate-button">Investigate</a>
                            {% else %}
                                N/A
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <p>All files are intact - no changes found.</p>
        {% endif %}
        <a href="/" class="button">Refresh Dashboard</a>
    </div>
</body>
</html>
"""

# Investigate page
investigate_template = """
<!doctype html>
<html>
<head>
    <title>Investigate Change - {{ file_path }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; }
        table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .container { max-width: 800px; margin: 0 auto; }
        a.button { 
            display: inline-block; 
            padding: 10px 15px; 
            background: #007BFF; 
            color: white; 
            text-decoration: none; 
            border-radius: 5px; 
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Investigate Change</h1>
        <h2>{{ file_path }}</h2>
        <table>
            <tr><th>Attribute</th><th>Value</th></tr>
            <tr><td>Baseline Checksum</td><td>{{ baseline_checksum }}</td></tr>
            <tr><td>Current Checksum</td><td>{{ current_checksum }}</td></tr>
            <tr><td>File Size</td><td>{{ file_size }} bytes</td></tr>
            <tr><td>Last Modified</td><td>{{ last_modified }}</td></tr>
            <tr><td>Permissions</td><td>{{ file_permissions }}</td></tr>
        </table>
        <a href="/" class="button">Back to Dashboard</a>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    baseline = load_baseline()
    issues = verify_integrity(baseline)
    return render_template_string(dashboard_template, issues=issues)

@app.route("/approve")
def approve_change():
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

    baseline_file = os.path.join(os.path.dirname(__file__), '..', 'baseline_checksums.txt')
    try:
        with open(baseline_file, 'w') as f:
            for path, checksum in baseline.items():
                f.write(f"{checksum}  {path}\n")
    except Exception as e:
        return f"Error updating baseline: {e}", 500

    return redirect("/")

@app.route("/investigate")
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
    except Exception as e:
        return f"Error retrieving file info: {e}", 500

    return render_template_string(investigate_template,
                                  file_path=file_path,
                                  baseline_checksum=baseline_checksum,
                                  current_checksum=current_checksum,
                                  file_size=file_size,
                                  last_modified=last_modified,
                                  file_permissions=file_permissions)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=11010)
