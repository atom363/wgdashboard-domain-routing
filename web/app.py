"""
Flask application for Domain Routing Plugin web server.
"""

import os
from flask import Flask, send_from_directory
from api import api
from auth import generate_token


def create_app(config: dict, database, wg_configs: dict = None, routing_engine=None) -> Flask:
    """
    Create and configure the Flask application.
    
    Args:
        config: Plugin configuration dictionary
        database: Database instance
        wg_configs: WireGuard configurations dictionary
        routing_engine: Routing engine instance
    
    Returns:
        Configured Flask application
    """
    # Get the directory containing the web module
    web_dir = os.path.dirname(os.path.abspath(__file__))
    static_dir = os.path.join(web_dir, 'static')
    
    app = Flask(__name__, static_folder=static_dir, static_url_path='/static')
    
    # Configure app
    app.config['AUTH_ENABLED'] = config.get('auth_enabled', True)
    app.config['AUTH_TOKEN'] = config.get('auth_token', '')
    app.config['DATABASE'] = database
    app.config['WG_CONFIGS'] = wg_configs or {}
    app.config['ROUTING_ENGINE'] = routing_engine
    
    # Register API blueprint
    app.register_blueprint(api)
    
    # Serve index.html for root path
    @app.route('/')
    def index():
        return send_from_directory(static_dir, 'index.html')
    
    # Health check endpoint (no auth required)
    @app.route('/health')
    def health():
        return {'status': 'ok'}
    
    return app


def run_server(app: Flask, host: str = '127.0.0.1', port: int = 8081):
    """
    Run the Flask development server.
    
    Note: For production, use a proper WSGI server.
    """
    # Disable Flask's reloader in threaded context
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
