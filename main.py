"""
Domain Routing Plugin for WGDashboard
Main entry point - starts web server and routing engine.
"""

import os
import sys
import logging
import configparser
import secrets
import importlib.util

# Get plugin directory
plugin_dir = os.path.dirname(os.path.abspath(__file__))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[DomainRouting] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_module_from_file(module_name: str, file_path: str):
    """Load a Python module from an absolute file path."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def generate_token() -> str:
    """Generate a secure random token."""
    return secrets.token_urlsafe(32)


def load_config(config_path: str) -> dict:
    """Load plugin configuration from INI file."""
    config = configparser.ConfigParser()
    
    defaults = {
        'port': 8081,
        'host': '127.0.0.1',
        'auth_enabled': True,
        'auth_token': '',
        'db_path': os.path.join(plugin_dir, 'db', 'routing_rules.db'),
        'monitoring_interval': 30,
        'dnsmasq_config_path': '/etc/dnsmasq.d/wgdashboard-domains.conf'
    }
    
    if os.path.exists(config_path):
        config.read(config_path)
        
        if 'WebServer' in config:
            defaults['port'] = config.getint('WebServer', 'port', fallback=defaults['port'])
            defaults['host'] = config.get('WebServer', 'host', fallback=defaults['host'])
            defaults['auth_enabled'] = config.getboolean('WebServer', 'auth_enabled', fallback=defaults['auth_enabled'])
            defaults['auth_token'] = config.get('WebServer', 'auth_token', fallback=defaults['auth_token'])
        
        if 'Database' in config:
            defaults['db_path'] = config.get('Database', 'path', fallback=defaults['db_path'])
        
        if 'Routing' in config:
            defaults['monitoring_interval'] = config.getint('Routing', 'monitoring_interval', fallback=defaults['monitoring_interval'])
            defaults['dnsmasq_config_path'] = config.get('Routing', 'dnsmasq_config_path', fallback=defaults['dnsmasq_config_path'])
    
    if defaults['auth_enabled'] and not defaults['auth_token']:
        defaults['auth_token'] = generate_token()
        save_auth_token(config_path, defaults['auth_token'])
        logger.info(f"Generated new auth token: {defaults['auth_token']}")
    
    return defaults


def save_auth_token(config_path: str, token: str):
    """Save the generated auth token to config file."""
    config = configparser.ConfigParser()
    
    if os.path.exists(config_path):
        config.read(config_path)
    
    if 'WebServer' not in config:
        config['WebServer'] = {}
    
    config['WebServer']['auth_token'] = token
    
    with open(config_path, 'w') as f:
        config.write(f)


def main(WireguardConfigurations: dict = None):
    """
    Main entry point for the Domain Routing Plugin.
    Called by WGDashboard when the plugin is loaded.
    """
    logger.info("=" * 50)
    logger.info("Domain Routing Plugin starting...")
    logger.info("=" * 50)
    
    # Load modules using importlib with absolute paths
    modules_dir = os.path.join(plugin_dir, 'modules')
    web_dir = os.path.join(plugin_dir, 'web')
    
    # Load module dependencies first (order matters for internal imports)
    load_module_from_file('ipset_manager', os.path.join(modules_dir, 'ipset_manager.py'))
    load_module_from_file('iptables_manager', os.path.join(modules_dir, 'iptables_manager.py'))
    load_module_from_file('policy_routing', os.path.join(modules_dir, 'policy_routing.py'))
    load_module_from_file('dnsmasq_integration', os.path.join(modules_dir, 'dnsmasq_integration.py'))
    
    database_mod = load_module_from_file('database', os.path.join(modules_dir, 'database.py'))
    wg_interface_mod = load_module_from_file('wg_interface', os.path.join(modules_dir, 'wg_interface.py'))
    routing_engine_mod = load_module_from_file('routing_engine', os.path.join(modules_dir, 'routing_engine.py'))
    
    load_module_from_file('auth', os.path.join(web_dir, 'auth.py'))
    load_module_from_file('api', os.path.join(web_dir, 'api.py'))
    app_mod = load_module_from_file('app', os.path.join(web_dir, 'app.py'))
    
    Database = database_mod.Database
    WgInterface = wg_interface_mod.WgInterface
    RoutingEngine = routing_engine_mod.RoutingEngine
    create_app = app_mod.create_app
    run_server = app_mod.run_server
    
    # Load configuration
    config_path = os.path.join(plugin_dir, 'config.ini')
    config = load_config(config_path)
    
    logger.info(f"Web server will listen on {config['host']}:{config['port']}")
    logger.info(f"Database path: {config['db_path']}")
    logger.info(f"Auth enabled: {config['auth_enabled']}")
    
    # Initialize database
    try:
        db = Database(config['db_path'])
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return
    
    # Initialize WireGuard interface helper
    wg_interface = WgInterface(WireguardConfigurations)
    
    # Initialize routing engine
    routing_engine = RoutingEngine(
        db=db,
        wg_interface=wg_interface,
        dnsmasq_config_path=config['dnsmasq_config_path'],
        monitoring_interval=config['monitoring_interval']
    )
    
    # Create Flask application
    app_config = {
        'auth_enabled': config['auth_enabled'],
        'auth_token': config['auth_token']
    }
    
    app = create_app(
        config=app_config,
        database=db,
        wg_configs=WireguardConfigurations,
        routing_engine=routing_engine
    )
    
    # Start routing engine in background
    routing_engine.start()
    
    # Print access info
    logger.info("-" * 50)
    logger.info(f"Web UI available at: http://{config['host']}:{config['port']}")
    if config['auth_enabled'] and config['auth_token']:
        logger.info(f"Access with token: http://{config['host']}:{config['port']}?token={config['auth_token']}")
    logger.info("-" * 50)
    
    # Run Flask server (blocking)
    try:
        run_server(app, host=config['host'], port=config['port'])
    except Exception as e:
        logger.error(f"Web server error: {e}")
    finally:
        logger.info("Shutting down routing engine...")
        routing_engine.stop()
        logger.info("Domain Routing Plugin stopped")


if __name__ == '__main__':
    main({})
