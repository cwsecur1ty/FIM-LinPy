import requests
from utils.config_handler import load_config

def check_hash_virustotal(file_hash):
    """
    Check a file hash against VirusTotal's database
    Returns dict with results or error message
    """
    config = load_config()
    api_key = config.get('virustotal_api_key')
    
    if not api_key:
        return {'error': 'VirusTotal API key not configured'}
    
    if not config.get('enable_virustotal', False):
        return {'error': 'VirusTotal integration is disabled'}

    headers = {
        'x-apikey': api_key
    }
    
    try:
        # Use VT v3 API
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            results = data.get('data', {}).get('attributes', {})
            
            stats = results.get('last_analysis_stats', {})
            return {
                'found': True,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'total_scans': sum(stats.values()),
                'scan_date': results.get('last_analysis_date'),
                'meaningful_name': results.get('meaningful_name', 'N/A'),
                'type_description': results.get('type_description', 'N/A')
            }
        elif response.status_code == 404:
            return {'found': False, 'message': 'Hash not found in VirusTotal database'}
        else:
            return {'error': f'VirusTotal API error: {response.status_code}'}
            
    except Exception as e:
        return {'error': f'Error checking VirusTotal: {str(e)}'}