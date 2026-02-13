"""
WireGuard interface helper for Domain Routing Plugin.
Provides access to WireGuard configurations from WGDashboard.
"""

import logging
from typing import Optional, Any
import threading

logger = logging.getLogger(__name__)

# Thread lock for accessing shared WG configs
_wg_lock = threading.Lock()


class WgInterface:
    """Helper class for accessing WireGuard configurations."""
    
    def __init__(self, wg_configs: dict = None):
        """
        Initialize WireGuard interface helper.
        
        Args:
            wg_configs: WireGuard configurations dictionary from WGDashboard
        """
        self._configs = wg_configs or {}
    
    def update_configs(self, wg_configs: dict):
        """Update the WireGuard configurations reference."""
        with _wg_lock:
            self._configs = wg_configs or {}
    
    def list_configurations(self) -> list[str]:
        """
        List all available WireGuard configuration names.
        
        Returns:
            List of configuration names (e.g., ["wg0", "wg1"])
        """
        with _wg_lock:
            return list(self._configs.keys())
    
    def get_configuration(self, name: str) -> Optional[Any]:
        """
        Get a WireGuard configuration object.
        
        Args:
            name: Configuration name
        
        Returns:
            Configuration object or None
        """
        with _wg_lock:
            # Try exact match first
            config = self._configs.get(name)
            if config:
                return config
            
            # Try case-insensitive match
            for k, v in self._configs.items():
                if k.lower() == name.lower():
                    return v
                    
            return None
    
    def get_configuration_json(self, name: str) -> Optional[dict]:
        """
        Get a WireGuard configuration as JSON/dict.
        
        Args:
            name: Configuration name
        
        Returns:
            Configuration dictionary or None
        """
        config = self.get_configuration(name)
        if not config:
            return None
        
        try:
            return config.toJson()
        except Exception as e:
            logger.error(f"Failed to get JSON for config {name}: {e}")
            return None
    
    def _extract_peers(self, json_data: dict) -> Any:
        """Helper to extract peers from various possible WGDashboard JSON structures."""
        if not isinstance(json_data, dict):
            return []
            
        # 1. Direct keys (common in different versions)
        for key in ['Peers', 'peer_data', 'peers', 'Peer', 'PeerData', 'clients']:
            val = json_data.get(key)
            if val:
                return val
        
        # 2. Nested in Configuration
        config = json_data.get('Configuration')
        if isinstance(config, dict):
            for key in ['Peers', 'peer_data', 'peers', 'Peer', 'PeerData']:
                val = config.get(key)
                if val:
                    return val
        
        # 3. Search all values for a list/dict that looks like peers
        for val in json_data.values():
            if isinstance(val, list) and len(val) > 0:
                # Check if first element looks like a peer
                item = val[0]
                if isinstance(item, dict) and any(k in item for k in ['id', 'public_key', 'allowed_ip', 'allowed_ips', 'endpoint']):
                    return val
            elif isinstance(val, dict) and len(val) > 0:
                # Check if it's a dict of peer dicts (keys are public keys)
                first_val = next(iter(val.values()))
                if isinstance(first_val, dict) and any(k in first_val for k in ['id', 'public_key', 'allowed_ip', 'allowed_ips', 'endpoint']):
                    return val
                    
        return []

    def list_peers(self, config_name: str) -> list[dict]:
        """
        List all peers for a WireGuard configuration.
        
        Args:
            config_name: Configuration name
        
        Returns:
            List of peer dictionaries
        """
        logger.info(f"list_peers called for config: {config_name}")
        config_obj = self.get_configuration(config_name)
        if not config_obj:
            logger.warning(f"Configuration {config_name} not found in {self.list_configurations()}")
            return []
            
        peers_data = []
        # Priority 1: Direct .Peers attribute on the object (WGDashboard v4+)
        if hasattr(config_obj, 'Peers'):
            logger.info(f"Found .Peers attribute on {config_name}")
            peers_data = config_obj.Peers
        else:
            logger.info(f"No .Peers attribute on {config_name}, falling back to JSON")
            # Priority 2: Try extracting from JSON (fallback/older versions)
            json_data = self.get_configuration_json(config_name)
            if json_data:
                peers_data = self._extract_peers(json_data)
        
        logger.info(f"Peers data type: {type(peers_data)}, length: {len(peers_data) if peers_data else 0}")
        
        peers = []
        
        # Handle both list of dicts and dict of dicts
        if isinstance(peers_data, dict):
            for p_id, peer_dict in peers_data.items():
                if not isinstance(peer_dict, dict):
                    continue
                self._add_peer_to_list(peers, p_id, peer_dict)
        elif isinstance(peers_data, list):
            for peer in peers_data:
                # Handle case where peer might be an object or a dict
                if isinstance(peer, dict):
                    peer_dict = peer
                    p_id = peer_dict.get('id') or peer_dict.get('public_key') or peer_dict.get('publicKey') or ''
                elif hasattr(peer, '__dict__'):
                    # If it's an object, try to use its attributes
                    peer_dict = peer.__dict__
                    p_id = getattr(peer, 'id', '') or getattr(peer, 'public_key', '') or ''
                else:
                    continue
                
                self._add_peer_to_list(peers, p_id, peer_dict)
        
        logger.info(f"Returning {len(peers)} processed peers")
        return peers

    def _add_peer_to_list(self, peers: list, p_id: str, peer_data: Any):
        """Helper to normalize peer data and add to list."""
        def get_v(obj, keys, default=''):
            if isinstance(keys, str):
                keys = [keys]
            
            for key in keys:
                if isinstance(obj, dict):
                    val = obj.get(key)
                else:
                    val = getattr(obj, key, None)
                
                if val is not None:
                    return val
            return default

        peers.append({
            'id': p_id or get_v(peer_data, ['id', 'public_key', 'publicKey']),
            'name': get_v(peer_data, ['name', 'remark', 'comment']),
            'public_key': p_id or get_v(peer_data, ['id', 'public_key', 'publicKey']),
            'allowed_ip': get_v(peer_data, ['allowed_ip', 'allowed_ips']),
            'endpoint': get_v(peer_data, ['endpoint']),
            'status': get_v(peer_data, ['status'], 'unknown'),
            'latest_handshake': get_v(peer_data, ['latest_handshake']),
            'transfer_rx': get_v(peer_data, ['cumu_receive', 'total_receive'], 0),
            'transfer_tx': get_v(peer_data, ['cumu_sent', 'total_sent'], 0)
        })

    
    def get_peer(self, config_name: str, peer_id: str) -> Optional[dict]:
        """
        Get a specific peer by ID/public key.
        
        Args:
            config_name: Configuration name
            peer_id: Peer ID or public key
        
        Returns:
            Peer dictionary or None
        """
        peers = self.list_peers(config_name)
        
        for peer in peers:
            if peer['id'] == peer_id or peer['public_key'] == peer_id:
                return peer
        
        return None
    
    def find_peer_by_public_key(self, public_key: str) -> Optional[tuple[str, dict]]:
        """
        Find a peer by public key across all configurations.
        
        Args:
            public_key: Peer's public key
        
        Returns:
            Tuple of (config_name, peer_dict) or None
        """
        for config_name in self.list_configurations():
            peers = self.list_peers(config_name)
            for peer in peers:
                if peer['public_key'] == public_key:
                    return config_name, peer
        
        return None
    
    def get_interface_name(self, config_name: str) -> Optional[str]:
        """
        Get the WireGuard interface name for a configuration.
        
        The interface name is typically the same as the configuration name
        (e.g., "wg0" config -> "wg0" interface).
        
        Args:
            config_name: Configuration name
        
        Returns:
            Interface name or None
        """
        if config_name in self.list_configurations():
            # In WGDashboard, config name == interface name
            return config_name
        return None
    
    def is_interface_up(self, interface: str) -> bool:
        """
        Check if a WireGuard interface is up and running.
        
        Args:
            interface: Interface name
        
        Returns:
            True if interface is up
        """
        json_data = self.get_configuration_json(interface)
        if not json_data:
            return False
        
        status = json_data.get('Status', 'unknown')
        return status.lower() == 'running'
    
    def get_configuration_status(self, config_name: str) -> str:
        """
        Get the status of a WireGuard configuration.
        
        Args:
            config_name: Configuration name
        
        Returns:
            Status string ('running', 'stopped', 'unknown')
        """
        json_data = self.get_configuration_json(config_name)
        if not json_data:
            return 'unknown'
        
        return json_data.get('Status', 'unknown').lower()
    
    def get_peer_endpoint(self, config_name: str, peer_id: str) -> Optional[str]:
        """
        Get the endpoint address for a peer.
        
        Args:
            config_name: Configuration name
            peer_id: Peer ID
        
        Returns:
            Endpoint string (IP:port) or None
        """
        peer = self.get_peer(config_name, peer_id)
        if peer:
            return peer.get('endpoint')
        return None
    
    def get_peer_allowed_ips(self, config_name: str, peer_id: str) -> list[str]:
        """
        Get the allowed IPs for a peer.
        
        Args:
            config_name: Configuration name
            peer_id: Peer ID
        
        Returns:
            List of allowed IP/CIDR strings
        """
        peer = self.get_peer(config_name, peer_id)
        if not peer:
            return []
        
        allowed_ip = peer.get('allowed_ip', '')
        if not allowed_ip:
            return []
        
        # Can be comma-separated
        return [ip.strip() for ip in allowed_ip.split(',') if ip.strip()]
