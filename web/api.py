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
    configs = []
    
    for name, config in wg_configs.items():
        try:
            json_data = config.toJson()
            configs.append({
                'name': name,
                'status': json_data.get('Status', 'unknown'),
                'address': json_data.get('Address', ''),
                'peer_count': len(json_data.get('Peers', []))
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
    wg_configs = get_wg_configs()
    
    if config_name not in wg_configs:
        return jsonify({
            'status': False,
            'message': f'Configuration "{config_name}" not found'
        }), 404
    
    try:
        config = wg_configs[config_name]
        json_data = config.toJson()
        peers_data = json_data.get('Peers', [])
        
        peers = []
        for peer in peers_data:
            peers.append({
                'id': peer.get('id', ''),
                'name': peer.get('name', ''),
                'public_key': peer.get('id', ''),  # id is usually the public key
                'allowed_ips': peer.get('allowed_ip', ''),
                'endpoint': peer.get('endpoint', ''),
                'status': peer.get('status', 'unknown')
            })
        
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
