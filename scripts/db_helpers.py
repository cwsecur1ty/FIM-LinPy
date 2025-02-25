import sqlite3, json, time, os

DB_FILENAME = os.path.join(os.path.dirname(__file__), '..', 'data', 'vuln_scans.db')

def init_db():
    """Initialize the database and create the package_scans table if it doesn't exist."""
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS package_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package TEXT NOT NULL,
            version TEXT NOT NULL,
            vulns TEXT,
            last_scanned TEXT,
            UNIQUE(package, version)
        )
    """)
    conn.commit()
    conn.close()

def update_scan_result(package, version, vulns):
    """Insert or update a scan result for the given package."""
    last_scanned = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    conn = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE package_scans 
        SET vulns = ?, last_scanned = ?
        WHERE package = ? AND version = ?
    """, (json.dumps(vulns), last_scanned, package, version))
    if cursor.rowcount == 0:
        cursor.execute("""
            INSERT INTO package_scans (package, version, vulns, last_scanned)
            VALUES (?, ?, ?, ?)
        """, (package, version, json.dumps(vulns), last_scanned))
    conn.commit()
    conn.close()

def get_all_scans():
    """Retrieve all scan records from the database as a list of dictionaries."""
    conn = sqlite3.connect(DB_FILENAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT package, version, vulns, last_scanned FROM package_scans")
    rows = cursor.fetchall()
    conn.close()
    results = []
    for row in rows:
        try:
            vulns = json.loads(row["vulns"]) if row["vulns"] else []
        except Exception:
            vulns = []
        results.append({
            "package": row["package"],
            "version": row["version"],
            "vulns": vulns,
            "last_scanned": row["last_scanned"]
        })
    return results
