from flask import Flask
from scripts.db_helpers import init_db
from routes.dashboard import bp as dashboard_bp
from routes.vulnerability import bp as vulnerability_bp
from routes.accounts import bp as accounts_bp
from routes.fim import bp as fim_bp
from routes.config import bp as config_bp
from routes.threat_hunting import bp as threat_hunting_bp

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Replace with a secure secret key

# Initialize the database
init_db()

# Register blueprints
app.register_blueprint(dashboard_bp)
app.register_blueprint(vulnerability_bp)
app.register_blueprint(accounts_bp)
app.register_blueprint(fim_bp)
app.register_blueprint(config_bp)
app.register_blueprint(threat_hunting_bp)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=11010)