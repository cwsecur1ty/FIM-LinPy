from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from utils.config_handler import load_config, save_config
from scripts.virustotal_helper import check_hash_virustotal
import hashlib
import os
import json
import time
import stat
import pwd
import grp
import datetime
import mimetypes
from scripts.integrity_check import compute_sha256, load_baseline
import sqlite3

bp = Blueprint('threat_hunting', __name__, url_prefix='/threat-hunting')

# Initialize the database with threat hunting tables
def init_threat_hunting_db():
    # Use the data directory for database storage
    db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'vuln_scans.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Table for storing known malicious hashes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malicious_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT NOT NULL UNIQUE,
            description TEXT,
            source TEXT,
            date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Table for storing file scan history
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            hash TEXT NOT NULL,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT,
            scan_type TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'vuln_scans.db')
    return sqlite3.connect(db_path)

@bp.route('/')
def index():
    config = load_config()
    return render_template('threat_hunting/index.html',
                         virustotal_enabled=config.get('enable_virustotal', False),
                         virustotal_api_key=config.get('virustotal_api_key', ''))

# Get detailed metadata for a file
def get_file_metadata(file_path):
    """
    Extract detailed metadata from a file.
    
    This function gathers information about file permissions, ownership,
    timestamps, and content type to provide comprehensive metadata.
    """
    metadata = {}
    
    try:
        # Only process if file exists
        if not os.path.exists(file_path):
            metadata['error'] = 'File not found'
            return metadata
            
        # Basic file information
        file_stat = os.stat(file_path)
        
        # Get file size and format it
        size_bytes = file_stat.st_size
        metadata['size'] = size_bytes
        
        # Format size for human readability
        if size_bytes < 1024:
            metadata['size_human'] = f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            metadata['size_human'] = f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            metadata['size_human'] = f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            metadata['size_human'] = f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
        
        # File timestamps
        metadata['created'] = datetime.datetime.fromtimestamp(file_stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        metadata['modified'] = datetime.datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        metadata['accessed'] = datetime.datetime.fromtimestamp(file_stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')
        
        # File permissions in octal and human-readable format
        metadata['permissions_octal'] = oct(stat.S_IMODE(file_stat.st_mode))[2:]
        
        # Map the numeric permission to human-readable format
        perm_string = ""
        mode = stat.S_IMODE(file_stat.st_mode)
        
        # File type
        if stat.S_ISDIR(file_stat.st_mode):
            perm_string += "d"
        elif stat.S_ISLNK(file_stat.st_mode):
            perm_string += "l"
        else:
            perm_string += "-"
            
        # User permissions
        perm_string += "r" if mode & stat.S_IRUSR else "-"
        perm_string += "w" if mode & stat.S_IWUSR else "-"
        perm_string += "x" if mode & stat.S_IXUSR else "-"
        
        # Group permissions
        perm_string += "r" if mode & stat.S_IRGRP else "-"
        perm_string += "w" if mode & stat.S_IWGRP else "-"
        perm_string += "x" if mode & stat.S_IXGRP else "-"
        
        # Other permissions
        perm_string += "r" if mode & stat.S_IROTH else "-"
        perm_string += "w" if mode & stat.S_IWOTH else "-"
        perm_string += "x" if mode & stat.S_IXOTH else "-"
        
        metadata['permissions'] = perm_string
        
        # File ownership
        try:
            metadata['owner'] = pwd.getpwuid(file_stat.st_uid).pw_name
        except KeyError:
            metadata['owner'] = str(file_stat.st_uid)
            
        try:
            metadata['group'] = grp.getgrgid(file_stat.st_gid).gr_name
        except KeyError:
            metadata['group'] = str(file_stat.st_gid)
        
        # File type/MIME detection
        mime_type, encoding = mimetypes.guess_type(file_path)
        metadata['mime_type'] = mime_type if mime_type else "Unknown"
        metadata['encoding'] = encoding if encoding else "None"
        
        # Try to read the first few bytes to help identify file type
        # This is useful for files where the extension doesn't match content
        try:
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(8)  # Read just the first 8 bytes
                
                # Common file signatures
                if magic_bytes.startswith(b'\x7FELF'):
                    metadata['file_type'] = 'ELF executable'
                elif magic_bytes.startswith(b'\x4D\x5A'):
                    metadata['file_type'] = 'Windows executable'
                elif magic_bytes.startswith(b'\x89\x50\x4E\x47'):
                    metadata['file_type'] = 'PNG image'
                elif magic_bytes.startswith(b'\xFF\xD8\xFF'):
                    metadata['file_type'] = 'JPEG image'
                elif magic_bytes.startswith(b'\x25\x50\x44\x46'):
                    metadata['file_type'] = 'PDF document'
                # If we can't identify by magic bytes, we fall back to MIME type
                else:
                    metadata['file_type'] = metadata['mime_type']
        except Exception as e:
            # Errors can happen if file isn't readable, is a special file, etc.
            metadata['file_type'] = "Could not determine (access error)"
            
    except Exception as e:
        metadata['error'] = str(e)
    
    return metadata

@bp.route('/file-metadata', methods=['POST'])
def file_metadata():
    # Get the file path from request data instead of URL parameter
    file_path = request.json.get('file_path')
    if not file_path:
        return jsonify({'error': 'No file path provided'}), 400
    
    print(f"Metadata request for: {file_path}")
    
    # Load baseline and try to get metadata
    baseline = load_baseline()
    
    # Try to find the file in baseline
    if file_path in baseline:
        # Direct match
        metadata = get_file_metadata(file_path)
        return jsonify(metadata)
    
    # If no direct match, try normalized paths
    normalized_path = os.path.normpath(file_path)
    for path in baseline.keys():
        if os.path.normpath(path) == normalized_path:
            metadata = get_file_metadata(path)
            return jsonify(metadata)
    
    # If still not found, try to find closest match
    for path in baseline.keys():
        if path.endswith(file_path) or file_path.endswith(path):
            metadata = get_file_metadata(path)
            return jsonify(metadata)
    
    # If all else fails, just try to get metadata anyway
    try:
        metadata = get_file_metadata(file_path)
        if 'error' not in metadata:
            return jsonify(metadata)
    except Exception as e:
        print(f"Error getting metadata: {e}")
    
    return jsonify({'error': 'File not found in baseline'}), 404

@bp.route('/search', methods=['POST'])
def search():
    search_type = request.form.get('search_type')
    search_value = request.form.get('search_value')
    search_scope = request.form.get('search_scope', 'baseline') # baseline or filesystem
    max_results = 50  # Limit to prevent UI overload
    
    print(f"Search request - Type: {search_type}, Value: {search_value}, Scope: {search_scope}")
    results = []
    
    try:
        # First, search through baseline
        baseline = load_baseline()
        
        if search_type == 'hash' and search_scope == 'baseline':
            # Search for files matching the hash in baseline
            for file_path, stored_hash in baseline.items():
                if stored_hash == search_value:
                    results.append({
                        'file_path': file_path,
                        'hash': stored_hash,
                        'match_type': 'Baseline match'
                    })
                    # Hash should be unique, so we can break after finding it
                    break
        
        elif search_type == 'path' and search_scope == 'baseline':
            # Search for files matching the path pattern in baseline
            for file_path, stored_hash in baseline.items():
                if search_value in file_path:
                    results.append({
                        'file_path': file_path,
                        'hash': stored_hash,
                        'match_type': 'Baseline match'
                    })
                    # Stop if we reach the limit
                    if len(results) >= max_results:
                        break
        
        elif search_scope == 'filesystem':
            # New feature: Search entire filesystem
            print(f"Starting filesystem search for {search_type}: {search_value}")
            
            # Start at root directory or a specified path
            start_path = '/'
            count = 0
            
            for root, _, files in os.walk(start_path):
                # Skip certain system directories to improve performance
                if any(skip_dir in root for skip_dir in ['/proc', '/sys', '/dev', '/run/user']):
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        if search_type == 'path' and search_value in file_path:
                            # For path search, just check the path
                            file_hash = compute_sha256(file_path)
                            if file_hash:
                                results.append({
                                    'file_path': file_path,
                                    'hash': file_hash,
                                    'match_type': 'Filesystem match'
                                })
                                count += 1
                        
                        elif search_type == 'hash':
                            # For hash search, we need to compute the hash of each file
                            file_hash = compute_sha256(file_path)
                            if file_hash == search_value:
                                results.append({
                                    'file_path': file_path,
                                    'hash': file_hash,
                                    'match_type': 'Filesystem match'
                                })
                                count += 1
                        
                        # Check if we've reached the limit
                        if count >= max_results:
                            break
                    
                    except (PermissionError, FileNotFoundError):
                        # Skip files we can't access
                        continue
                
                # Check if we've reached the limit
                if count >= max_results:
                    break
        
        total_matches = len(results)
        limited_results = results[:max_results]
        
        return jsonify({
            'results': limited_results,
            'total_count': total_matches,
            'limited': total_matches > max_results
        })
    
    except Exception as e:
        print(f"Error in search: {str(e)}")
        return jsonify({'error': str(e)}), 500

@bp.route('/scan-directory', methods=['POST'])
def scan_directory():
    directory = request.form.get('directory')
    print(f"Scan directory request received for: {directory}")  # Debug log
    
    if not os.path.exists(directory):
        return jsonify({'error': 'Directory not found'}), 404
    
    try:
        results = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = compute_sha256(file_path)
                if file_hash:
                    results.append({
                        'file_path': file_path,
                        'hash': file_hash,
                        'match_type': 'Directory scan'
                    })
        
        print(f"Scan results: {len(results)} files found")  # Debug log
        return jsonify(results)
    
    except Exception as e:
        print(f"Error in directory scan: {str(e)}")  # Debug log
        return jsonify({'error': str(e)}), 500

@bp.route('/add-malicious-hash', methods=['POST'])
def add_malicious_hash():
    hash_value = request.form.get('hash')
    description = request.form.get('description')
    source = request.form.get('source')
    
    print(f"Adding malicious hash: {hash_value}")  # Debug log
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO malicious_hashes (hash, description, source)
            VALUES (?, ?, ?)
        ''', (hash_value, description, source))
        conn.commit()
        return jsonify({'status': 'success'})
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'Hash already exists'})
    except Exception as e:
        print(f"Error adding malicious hash: {str(e)}")  # Debug log
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# Virus total routes
@bp.route('/configure-virustotal', methods=['POST'])
def configure_virustotal():
    config = load_config()
    config['virustotal_api_key'] = request.form.get('api_key', '')
    config['enable_virustotal'] = request.form.get('enable_virustotal') == 'true'
    save_config(config)
    return redirect(url_for('threat_hunting.index'))

@bp.route('/check-virustotal', methods=['POST'])
def check_virustotal():
    file_hash = request.form.get('hash')
    if not file_hash:
        return jsonify({'error': 'No hash provided'})
    
    results = check_hash_virustotal(file_hash)
    return jsonify(results)

# Initialize the database tables when the bp is registered
init_threat_hunting_db()