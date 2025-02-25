from flask import Blueprint, render_template, request, redirect, url_for
from utils.config_handler import load_config, save_config

bp = Blueprint('config', __name__, url_prefix='/config')

@bp.route('/', methods=['GET'])
def index():
    config = load_config()
    return render_template('config/index.html', config=config)

@bp.route('/update', methods=['POST'])
def update_config():
    config = load_config()
    
    # Update API keys
    config['virustotal_api_key'] = request.form.get('virustotal_api_key', '')
    config['enable_virustotal'] = request.form.get('enable_virustotal') == 'true'
    
    # Add other configuration options here
    config['alert_on_change'] = request.form.get('alert_on_change') == 'true'
    
    save_config(config)
    return redirect(url_for('config.index'))