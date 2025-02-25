from flask import Flask
from scripts.db_helpers import init_db

def create_app():
    app = Flask(__name__)
    
    # Initialize the database
    init_db()
    
    # Routes will be registered here later
    from app.routes import dashboard
    app.register_blueprint(dashboard.bp)
    
    return app