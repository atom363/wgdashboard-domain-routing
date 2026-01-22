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
            return self._configs.get(name)
    
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
    
    def list_peers(self, config_name: str) -> list[dict]:
        """
        List all peers for a WireGuard configuration.
        
        Args:
            config_name: Configuration name
        
        Returns:
            List of peer dictionaries
        """
        json_data = self.get_configuration_json(config_name)
        if not json_data:
            return []
        
        peers_data = json_data.get('Peers', [])
        peers = []
        
        for peer in peers_data:
            peers.append({
                'id': peer.get('id', ''),
                'name': peer.get('name', ''),
                'public_key': peer.get('id', ''),  # 'id' is usually the public key
                'allowed_ip': peer.get('allowed_ip', ''),
                'endpoint': peer.get('endpoint', ''),
                'status': peer.get('status', 'unknown'),
                'latest_handshake': peer.get('latest_handshake', ''),
                'transfer_rx': peer.get('cumu_receive', 0),
                'transfer_tx': peer.get('cumu_sent', 0)
            })
        
        return peers
    
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
