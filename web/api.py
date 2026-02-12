"""
REST API endpoints for Domain Routing Plugin.
"""

from flask import Blueprint, jsonify, request, current_app
from auth import auth_required

api = Blueprint('api', __name__, url_prefix='/api')


def get_db():
    """Get database instance from app context."""
    return current_app.config['DATABASE']


def get_wg_configs():
    """Get WireGuard configurations from app context."""
    return current_app.config.get('WG_CONFIGS', {})


def get_routing_engine():
    """Get routing engine from app context."""
    return current_app.config.get('ROUTING_ENGINE')


# Status & Health

@api.route('/status', methods=['GET'])
@auth_required
def get_status():
    """Get plugin status and statistics."""
    db = get_db()
    stats = db.get_stats()
    
    engine = get_routing_engine()
    engine_status = "running" if engine and engine.is_running() else "stopped"
    
    return jsonify({
        'status': True,
        'data': {
            'engine_status': engine_status,
            'total_rules': stats['total_rules'],
            'enabled_rules': stats['enabled_rules'],
            'active_rules': stats['active_rules']
        }
    })


# WireGuard Configurations

@api.route('/wg/configurations', methods=['GET'])
@auth_required
def get_wg_configurations():
    """List available WireGuard configurations."""
    wg_configs = get_wg_configs()
    engine = get_routing_engine()
    configs = []
    
    for name, config in wg_configs.items():
        try:
            json_data = config.toJson()
            
            # Get peer count using the wg interface helper for consistency
            peer_count = 0
            if engine and engine.wg:
                peer_count = len(engine.wg.list_peers(name))
            else:
                # Fallback if engine not yet ready
                peers_data = json_data.get('Peers') or json_data.get('peer_data') or json_data.get('peers') or []
                peer_count = len(peers_data)

            configs.append({
                'name': name,
                'status': json_data.get('Status') or json_data.get('status', 'unknown'),
                'address': json_data.get('Address') or json_data.get('address', ''),
                'peer_count': peer_count
            })
        except Exception as e:
            configs.append({
                'name': name,
                'status': 'error',
                'error': str(e)
            })
    
    return jsonify({
        'status': True,
        'data': configs
    })


@api.route('/wg/peers/<config_name>', methods=['GET'])
@auth_required
def get_wg_peers(config_name: str):
    """List peers for a WireGuard configuration."""
    engine = get_routing_engine()
    if not engine or not engine.wg:
        return jsonify({
            'status': False,
            'message': 'WireGuard interface helper not available'
        }), 500
    
    # Ensure wg_interface has the latest configs from app context
    wg_configs = get_wg_configs()
    engine.wg.update_configs(wg_configs)
    
    current_app.logger.info(f"API: get_wg_peers called for {config_name}. Available configs: {list(wg_configs.keys())}")
    
    try:
        peers = engine.wg.list_peers(config_name)
        current_app.logger.info(f"API: list_peers returned {len(peers)} peers")
        
        if not peers and config_name not in engine.wg.list_configurations():
             return jsonify({
                'status': False,
                'message': f'Configuration "{config_name}" not found'
            }), 404

        return jsonify({
            'status': True,
            'data': peers
        })
    except Exception as e:
        return jsonify({
            'status': False,
            'message': str(e)
        }), 500


# Routing Rules CRUD

@api.route('/rules', methods=['GET'])
@auth_required
def get_rules():
    """List all routing rules."""
    db = get_db()
    rules = db.get_all_rules()
    
    # Include applied state for each rule
    rules_data = []
    for rule in rules:
        rule_dict = rule.to_dict()
        state = db.get_applied_state(rule.id)
        rule_dict['applied_state'] = {
            'status': state.status if state else 'not_applied',
            'ipset_name': state.ipset_name if state else None,
            'applied_ips': state.applied_ips if state else '[]',
            'last_applied': state.last_applied if state else None
        }
        rules_data.append(rule_dict)
    
    return jsonify({
        'status': True,
        'data': rules_data
    })


@api.route('/rules/<int:rule_id>', methods=['GET'])
@auth_required
def get_rule(rule_id: int):
    """Get a single routing rule."""
    db = get_db()
    rule = db.get_rule_by_id(rule_id)
    
    if not rule:
        return jsonify({
            'status': False,
            'message': f'Rule {rule_id} not found'
        }), 404
    
    rule_dict = rule.to_dict()
    state = db.get_applied_state(rule.id)
    rule_dict['applied_state'] = {
        'status': state.status if state else 'not_applied',
        'ipset_name': state.ipset_name if state else None,
        'applied_ips': state.applied_ips if state else '[]',
        'last_applied': state.last_applied if state else None
    }
    
    return jsonify({
        'status': True,
        'data': rule_dict
    })


@api.route('/rules', methods=['POST'])
@auth_required
def create_rule():
    """Create a new routing rule."""
    from database import RoutingRule
    
    data = request.get_json()
    if not data:
        return jsonify({
            'status': False,
            'message': 'No JSON data provided'
        }), 400
    
    # Validate required fields
    required = ['name', 'domain', 'target_type']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({
            'status': False,
            'message': f'Missing required fields: {", ".join(missing)}'
        }), 400
    
    # Validate target_type
    if data['target_type'] not in ['default_gateway', 'wireguard_peer']:
        return jsonify({
            'status': False,
            'message': 'target_type must be "default_gateway" or "wireguard_peer"'
        }), 400
    
    # Validate WireGuard peer target
    if data['target_type'] == 'wireguard_peer':
        if not data.get('target_config'):
            return jsonify({
                'status': False,
                'message': 'target_config is required for wireguard_peer target'
            }), 400
    
    db = get_db()
    
    # Auto-assign fwmark and routing_table if not provided
    if not data.get('fwmark'):
        data['fwmark'] = db.get_next_fwmark()
    if not data.get('routing_table'):
        data['routing_table'] = data['fwmark']  # Use same value as fwmark
    
    rule = RoutingRule(
        name=data['name'],
        domain=data['domain'],
        target_type=data['target_type'],
        target_config=data.get('target_config'),
        target_peer=data.get('target_peer'),
        fwmark=data['fwmark'],
        routing_table=data['routing_table'],
        enabled=data.get('enabled', True),
        priority=data.get('priority', 100)
    )
    
    rule = db.create_rule(rule)
    
    return jsonify({
        'status': True,
        'message': 'Rule created successfully',
        'data': rule.to_dict()
    }), 201


@api.route('/rules/<int:rule_id>', methods=['PUT'])
@auth_required
def update_rule(rule_id: int):
    """Update an existing routing rule."""
    db = get_db()
    rule = db.get_rule_by_id(rule_id)
    
    if not rule:
        return jsonify({
            'status': False,
            'message': f'Rule {rule_id} not found'
        }), 404
    
    data = request.get_json()
    if not data:
        return jsonify({
            'status': False,
            'message': 'No JSON data provided'
        }), 400
    
    # Update fields
    if 'name' in data:
        rule.name = data['name']
    if 'domain' in data:
        rule.domain = data['domain']
    if 'target_type' in data:
        rule.target_type = data['target_type']
    if 'target_config' in data:
        rule.target_config = data['target_config']
    if 'target_peer' in data:
        rule.target_peer = data['target_peer']
    if 'fwmark' in data:
        rule.fwmark = data['fwmark']
    if 'routing_table' in data:
        rule.routing_table = data['routing_table']
    if 'enabled' in data:
        rule.enabled = data['enabled']
    if 'priority' in data:
        rule.priority = data['priority']
    
    if db.update_rule(rule):
        return jsonify({
            'status': True,
            'message': 'Rule updated successfully',
            'data': rule.to_dict()
        })
    else:
        return jsonify({
            'status': False,
            'message': 'Failed to update rule'
        }), 500


@api.route('/rules/<int:rule_id>', methods=['DELETE'])
@auth_required
def delete_rule(rule_id: int):
    """Delete a routing rule."""
    db = get_db()
    
    if not db.get_rule_by_id(rule_id):
        return jsonify({
            'status': False,
            'message': f'Rule {rule_id} not found'
        }), 404
    
    # Remove applied routing before deleting
    engine = get_routing_engine()
    if engine:
        engine.remove_rule(rule_id)
    
    if db.delete_rule(rule_id):
        return jsonify({
            'status': True,
            'message': 'Rule deleted successfully'
        })
    else:
        return jsonify({
            'status': False,
            'message': 'Failed to delete rule'
        }), 500


@api.route('/rules/<int:rule_id>/toggle', methods=['POST'])
@auth_required
def toggle_rule(rule_id: int):
    """Toggle a rule's enabled state."""
    db = get_db()
    
    new_state = db.toggle_rule(rule_id)
    if new_state is None:
        return jsonify({
            'status': False,
            'message': f'Rule {rule_id} not found'
        }), 404
    
    return jsonify({
        'status': True,
        'message': f'Rule {"enabled" if new_state else "disabled"} successfully',
        'data': {'enabled': new_state}
    })


@api.route('/rules/<int:rule_id>/apply', methods=['POST'])
@auth_required
def apply_rule(rule_id: int):
    """Force apply a single rule."""
    db = get_db()
    rule = db.get_rule_by_id(rule_id)
    
    if not rule:
        return jsonify({
            'status': False,
            'message': f'Rule {rule_id} not found'
        }), 404
    
    engine = get_routing_engine()
    if not engine:
        return jsonify({
            'status': False,
            'message': 'Routing engine not available'
        }), 500
    
    success, message = engine.apply_rule(rule)
    
    return jsonify({
        'status': success,
        'message': message
    })


@api.route('/rules/apply-all', methods=['POST'])
@auth_required
def apply_all_rules():
    """Force reapply all enabled rules."""
    engine = get_routing_engine()
    if not engine:
        return jsonify({
            'status': False,
            'message': 'Routing engine not available'
        }), 500
    
    results = engine.apply_all_rules()
    
    return jsonify({
        'status': True,
        'message': f'Applied {results["success"]} rules, {results["failed"]} failed',
        'data': results
    })


@api.route('/rules/cleanup', methods=['POST'])
@auth_required
def cleanup_rules():
    """Remove all applied routing rules from system."""
    engine = get_routing_engine()
    if not engine:
        return jsonify({
            'status': False,
            'message': 'Routing engine not available'
        }), 500
    
    engine.cleanup_all()
    
    return jsonify({
        'status': True,
        'message': 'All routing rules cleaned up'
    })


# Static Routes API

@api.route('/static-routes', methods=['GET'])
@auth_required
def get_static_routes():
    """List all static routes."""
    db = get_db()
    routes = db.get_all_static_routes()
    
    # Include applied state for each route
    routes_data = []
    for route in routes:
        route_dict = route.to_dict()
        state = db.get_static_route_applied_state(route.id)
        route_dict['applied_state'] = {
            'status': state['status'] if state else 'not_applied',
            'last_applied': state['last_applied'] if state else None
        }
        routes_data.append(route_dict)
    
    return jsonify({
        'status': True,
        'data': routes_data
    })


@api.route('/static-routes/<int:route_id>', methods=['GET'])
@auth_required
def get_static_route(route_id: int):
    """Get a single static route."""
    db = get_db()
    route = db.get_static_route_by_id(route_id)
    
    if not route:
        return jsonify({
            'status': False,
            'message': f'Static route {route_id} not found'
        }), 404
    
    route_dict = route.to_dict()
    state = db.get_static_route_applied_state(route.id)
    route_dict['applied_state'] = {
        'status': state['status'] if state else 'not_applied',
        'last_applied': state['last_applied'] if state else None
    }
    
    return jsonify({
        'status': True,
        'data': route_dict
    })


@api.route('/static-routes', methods=['POST'])
@auth_required
def create_static_route():
    """Create a new static route."""
    from database import StaticRoute
    
    data = request.get_json()
    if not data:
        return jsonify({
            'status': False,
            'message': 'No JSON data provided'
        }), 400
    
    # Validate required fields
    required = ['name', 'destination', 'target_type']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({
            'status': False,
            'message': f'Missing required fields: {", ".join(missing)}'
        }), 400
    
    # Validate target_type
    if data['target_type'] not in ['default_gateway', 'wireguard_peer', 'interface']:
        return jsonify({
            'status': False,
            'message': 'target_type must be "default_gateway", "wireguard_peer", or "interface"'
        }), 400
    
    # Validate WireGuard peer target
    if data['target_type'] == 'wireguard_peer' and not data.get('target_config'):
        return jsonify({
            'status': False,
            'message': 'target_config is required for wireguard_peer target'
        }), 400
    
    db = get_db()
    
    route = StaticRoute(
        name=data['name'],
        destination=data['destination'],
        gateway=data.get('gateway'),
        interface=data.get('interface'),
        target_type=data['target_type'],
        target_config=data.get('target_config'),
        target_peer=data.get('target_peer'),
        enabled=data.get('enabled', True),
        priority=data.get('priority', 100)
    )
    
    route = db.create_static_route(route)
    
    # Apply the route if enabled
    engine = get_routing_engine()
    if engine and route.enabled:
        engine.apply_static_route(route)
    
    return jsonify({
        'status': True,
        'message': 'Static route created successfully',
        'data': route.to_dict()
    }), 201


@api.route('/static-routes/<int:route_id>', methods=['PUT'])
@auth_required
def update_static_route(route_id: int):
    """Update an existing static route."""
    db = get_db()
    route = db.get_static_route_by_id(route_id)
    
    if not route:
        return jsonify({
            'status': False,
            'message': f'Static route {route_id} not found'
        }), 404
    
    data = request.get_json()
    if not data:
        return jsonify({
            'status': False,
            'message': 'No JSON data provided'
        }), 400
    
    # Update fields
    if 'name' in data:
        route.name = data['name']
    if 'destination' in data:
        route.destination = data['destination']
    if 'gateway' in data:
        route.gateway = data['gateway']
    if 'interface' in data:
        route.interface = data['interface']
    if 'target_type' in data:
        route.target_type = data['target_type']
    if 'target_config' in data:
        route.target_config = data['target_config']
    if 'target_peer' in data:
        route.target_peer = data['target_peer']
    if 'enabled' in data:
        route.enabled = data['enabled']
    if 'priority' in data:
        route.priority = data['priority']
    
    if db.update_static_route(route):
        # Re-apply the route if it's enabled
        engine = get_routing_engine()
        if engine:
            # Remove old route first
            engine.remove_static_route(route_id)
            # Apply new route if enabled
            if route.enabled:
                engine.apply_static_route(route)
        
        return jsonify({
            'status': True,
            'message': 'Static route updated successfully',
            'data': route.to_dict()
        })
    else:
        return jsonify({
            'status': False,
            'message': 'Failed to update static route'
        }), 500


@api.route('/static-routes/<int:route_id>', methods=['DELETE'])
@auth_required
def delete_static_route(route_id: int):
    """Delete a static route."""
    db = get_db()
    
    if not db.get_static_route_by_id(route_id):
        return jsonify({
            'status': False,
            'message': f'Static route {route_id} not found'
        }), 404
    
    # Remove applied route before deleting
    engine = get_routing_engine()
    if engine:
        engine.remove_static_route(route_id)
    
    if db.delete_static_route(route_id):
        return jsonify({
            'status': True,
            'message': 'Static route deleted successfully'
        })
    else:
        return jsonify({
            'status': False,
            'message': 'Failed to delete static route'
        }), 500


@api.route('/static-routes/<int:route_id>/toggle', methods=['POST'])
@auth_required
def toggle_static_route(route_id: int):
    """Toggle a static route's enabled state."""
    db = get_db()
    
    new_state = db.toggle_static_route(route_id)
    if new_state is None:
        return jsonify({
            'status': False,
            'message': f'Static route {route_id} not found'
        }), 404
    
    # Apply or remove the route based on new state
    engine = get_routing_engine()
    if engine:
        if new_state:
            route = db.get_static_route_by_id(route_id)
            if route:
                engine.apply_static_route(route)
        else:
            engine.remove_static_route(route_id)
    
    return jsonify({
        'status': True,
        'message': f'Static route {"enabled" if new_state else "disabled"} successfully',
        'data': {'enabled': new_state}
    })


@api.route('/static-routes/<int:route_id>/apply', methods=['POST'])
@auth_required
def apply_static_route_endpoint(route_id: int):
    """Force apply a single static route."""
    db = get_db()
    route = db.get_static_route_by_id(route_id)
    
    if not route:
        return jsonify({
            'status': False,
            'message': f'Static route {route_id} not found'
        }), 404
    
    engine = get_routing_engine()
    if not engine:
        return jsonify({
            'status': False,
            'message': 'Routing engine not available'
        }), 500
    
    # Remove old route first, then apply
    engine.remove_static_route(route_id)
    success, message = engine.apply_static_route(route)
    
    return jsonify({
        'status': success,
        'message': message
    })


@api.route('/static-routes/apply-all', methods=['POST'])
@auth_required
def apply_all_static_routes():
    """Force reapply all enabled static routes."""
    engine = get_routing_engine()
    if not engine:
        return jsonify({
            'status': False,
            'message': 'Routing engine not available'
        }), 500
    
    results = engine.apply_all_static_routes()
    
    return jsonify({
        'status': True,
        'message': f'Applied {results["success"]} static routes, {results["failed"]} failed',
        'data': results
    })
