"""
Routing Engine for Domain Routing Plugin.
Monitors database and applies/removes routing rules.
"""

import json
import socket
import logging
import threading
from time import sleep, time
from typing import Optional

from database import Database, RoutingRule, AppliedState
from ipset_manager import (
    get_ipset_name, get_ipset_name_v6, create_ipsets_for_rule, destroy_ipsets_for_rule, 
    add_ip_to_rule_ipset, list_ipset_entries, cleanup_all_ipsets
)
from iptables_manager import (
    add_mangle_rules_dual_stack, remove_mangle_rules_dual_stack, 
    cleanup_all_rules as cleanup_iptables
)
from policy_routing import (
    setup_default_gateway_routing, setup_wireguard_routing,
    cleanup_routing, get_default_gateway
)
from dnsmasq_integration import (
    update_and_reload as update_dnsmasq, cleanup as cleanup_dnsmasq
)
from wg_interface import WgInterface

logger = logging.getLogger(__name__)


def resolve_domain(domain: str) -> list[str]:
    """
    Resolve a domain name to both IPv4 and IPv6 addresses.
    
    Args:
        domain: Domain name to resolve
    
    Returns:
        List of IP addresses (both IPv4 and IPv6)
    """
    ips = []
    
    # Resolve IPv4 addresses
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        for result in results:
            ip = result[4][0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror as e:
        logger.debug(f"Failed to resolve IPv4 for {domain}: {e}")
    except Exception as e:
        logger.error(f"Error resolving IPv4 for {domain}: {e}")
    
    # Resolve IPv6 addresses
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET6)
        for result in results:
            ip = result[4][0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror as e:
        logger.debug(f"Failed to resolve IPv6 for {domain}: {e}")
    except Exception as e:
        logger.error(f"Error resolving IPv6 for {domain}: {e}")
    
    return ips


class RoutingEngine:
    """
    Engine that monitors and applies routing rules.
    """
    
    def __init__(self, db: Database, wg_interface: WgInterface, 
                 dnsmasq_config_path: str = "/etc/dnsmasq.d/wgdashboard-domains.conf",
                 monitoring_interval: int = 30):
        """
        Initialize the routing engine.
        
        Args:
            db: Database instance
            wg_interface: WireGuard interface helper
            dnsmasq_config_path: Path to dnsmasq configuration file
            monitoring_interval: Seconds between monitoring cycles
        """
        self.db = db
        self.wg = wg_interface
        self.dnsmasq_config_path = dnsmasq_config_path
        self.monitoring_interval = monitoring_interval
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
    
    def is_running(self) -> bool:
        """Check if the engine is running."""
        return self._running and self._thread and self._thread.is_alive()
    
    def start(self):
        """Start the routing engine monitoring loop."""
        if self.is_running():
            logger.warning("Routing engine already running")
            return
        
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._thread.start()
        logger.info("Routing engine started")
    
    def stop(self):
        """Stop the routing engine."""
        if not self._running:
            return
        
        logger.info("Stopping routing engine...")
        self._running = False
        self._stop_event.set()
        
        if self._thread:
            self._thread.join(timeout=5)
        
        logger.info("Routing engine stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop."""
        logger.info("Routing engine monitoring loop started")
        
        # Initial apply on start
        self.apply_all_rules()
        
        while self._running and not self._stop_event.is_set():
            try:
                # Sleep with interrupt capability
                if self._stop_event.wait(timeout=self.monitoring_interval):
                    break  # Stop event was set
                
                # Periodic sync
                self._sync_rules()
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
    
    def _sync_rules(self):
        """Synchronize applied rules with database state."""
        enabled_rules = self.db.get_enabled_rules()
        applied_states = {s.rule_id: s for s in self.db.get_all_applied_states()}
        
        # Apply new/changed rules
        for rule in enabled_rules:
            state = applied_states.get(rule.id)
            if not state or state.status != 'active':
                self.apply_rule(rule)
        
        # Update dnsmasq config
        self._update_dnsmasq_config()
    
    def _parse_peer_gateways(self, allowed_ip: str) -> tuple[Optional[str], Optional[str]]:
        """
        Parse peer allowed_ip string to extract IPv4 and IPv6 gateways.
        
        The first IPv4 address becomes the IPv4 gateway.
        The first IPv6 address becomes the IPv6 gateway.
        CIDR notation is stripped (e.g., '172.22.1.2/32' -> '172.22.1.2').
        
        Args:
            allowed_ip: Comma-separated allowed IPs (e.g., '172.22.1.2/32, fd22:1::2/128')
        
        Returns:
            Tuple of (ipv4_gateway, ipv6_gateway)
        """
        if not allowed_ip:
            return None, None
        
        ipv4_gateway = None
        ipv6_gateway = None
        
        # Split by comma and process each IP
        for ip_cidr in allowed_ip.split(','):
            ip_cidr = ip_cidr.strip()
            if not ip_cidr:
                continue
            
            # Strip CIDR notation
            ip = ip_cidr.split('/')[0]
            
            # Determine if IPv4 or IPv6
            if ':' in ip:
                # IPv6 address
                if ipv6_gateway is None:
                    ipv6_gateway = ip
            else:
                # IPv4 address
                if ipv4_gateway is None:
                    ipv4_gateway = ip
            
            # Stop if we have both
            if ipv4_gateway and ipv6_gateway:
                break
        
        return ipv4_gateway, ipv6_gateway

    def apply_rule(self, rule: RoutingRule) -> tuple[bool, str]:
        """
        Apply a single routing rule with dual-stack (IPv4 + IPv6) support.
        
        Args:
            rule: RoutingRule to apply
        
        Returns:
            Tuple of (success, message)
        """
        logger.info(f"Applying rule: {rule.name} (domain: {rule.domain})")
        
        ipset_name_v4 = get_ipset_name(rule.id)
        ipset_name_v6 = get_ipset_name_v6(rule.id)
        
        try:
            # Step 1: Create both IPv4 and IPv6 ipsets
            success, msg = create_ipsets_for_rule(rule.id)
            if not success:
                return self._mark_failed(rule, f"Failed to create ipsets: {msg}")
            
            # Step 2: Resolve domain and add IPs to appropriate ipsets
            ips = resolve_domain(rule.domain)
            ipv4_count = 0
            ipv6_count = 0
            for ip in ips:
                success, _ = add_ip_to_rule_ipset(rule.id, ip)
                if success:
                    if ':' in ip:
                        ipv6_count += 1
                    else:
                        ipv4_count += 1
            
            logger.info(f"Resolved {ipv4_count} IPv4 and {ipv6_count} IPv6 addresses for {rule.domain}")
            
            # Step 3: Add iptables and ip6tables mangle rules
            success, msg = add_mangle_rules_dual_stack(ipset_name_v4, ipset_name_v6, rule.fwmark, rule.id)
            if not success:
                return self._mark_failed(rule, f"Failed to add iptables rules: {msg}")
            
            # Step 4: Setup policy routing
            if rule.target_type == 'default_gateway':
                success, msg = setup_default_gateway_routing(rule.fwmark, rule.routing_table)
            elif rule.target_type == 'wireguard_peer':
                wg_interface = self.wg.get_interface_name(rule.target_config)
                if not wg_interface:
                    return self._mark_failed(rule, f"WireGuard config {rule.target_config} not found")
                
                # Get peer gateway IPs from allowed_ip
                ipv4_gateway = None
                ipv6_gateway = None
                
                if rule.target_peer:
                    # Specific peer selected - use its allowed IPs
                    peer = self.wg.get_peer(rule.target_config, rule.target_peer)
                    if peer:
                        ipv4_gateway, ipv6_gateway = self._parse_peer_gateways(peer.get('allowed_ip', ''))
                        logger.info(f"Using peer gateways: IPv4={ipv4_gateway}, IPv6={ipv6_gateway}")
                else:
                    # No specific peer - try to get first peer's IPs as default
                    peers = self.wg.list_peers(rule.target_config)
                    if peers:
                        ipv4_gateway, ipv6_gateway = self._parse_peer_gateways(peers[0].get('allowed_ip', ''))
                        logger.info(f"Using first peer gateways: IPv4={ipv4_gateway}, IPv6={ipv6_gateway}")
                
                success, msg = setup_wireguard_routing(
                    rule.fwmark, rule.routing_table, wg_interface,
                    ipv4_gateway=ipv4_gateway, ipv6_gateway=ipv6_gateway
                )
            else:
                return self._mark_failed(rule, f"Unknown target type: {rule.target_type}")
            
            if not success:
                return self._mark_failed(rule, f"Failed to setup routing: {msg}")
            
            # Mark as active
            state = AppliedState(
                rule_id=rule.id,
                ipset_name=ipset_name_v4,  # Store v4 name, v6 can be derived
                applied_ips=json.dumps(ips),
                status='active'
            )
            self.db.set_applied_state(state)
            
            logger.info(f"Successfully applied rule: {rule.name} ({ipv4_count} IPv4, {ipv6_count} IPv6)")
            return True, f"Rule applied ({ipv4_count} IPv4, {ipv6_count} IPv6 addresses)"
            
        except Exception as e:
            logger.exception(f"Exception applying rule {rule.name}")
            return self._mark_failed(rule, str(e))
    
    def _mark_failed(self, rule: RoutingRule, message: str) -> tuple[bool, str]:
        """Mark a rule as failed in the database."""
        state = AppliedState(
            rule_id=rule.id,
            ipset_name=get_ipset_name(rule.id),
            status='failed'
        )
        self.db.set_applied_state(state)
        logger.error(f"Rule {rule.name} failed: {message}")
        return False, message
    
    def remove_rule(self, rule_id: int) -> tuple[bool, str]:
        """
        Remove routing for a specific rule (both IPv4 and IPv6).
        
        Args:
            rule_id: ID of the rule to remove
        
        Returns:
            Tuple of (success, message)
        """
        rule = self.db.get_rule_by_id(rule_id)
        if not rule:
            return False, "Rule not found"
        
        logger.info(f"Removing rule: {rule.name}")
        
        ipset_name_v4 = get_ipset_name(rule_id)
        ipset_name_v6 = get_ipset_name_v6(rule_id)
        errors = []
        
        # Remove iptables and ip6tables rules
        success, msg = remove_mangle_rules_dual_stack(ipset_name_v4, ipset_name_v6, rule.fwmark, rule_id)
        if not success:
            errors.append(f"iptables: {msg}")
        
        # Remove policy routing
        success, msg = cleanup_routing(rule.fwmark, rule.routing_table)
        if not success:
            errors.append(f"routing: {msg}")
        
        # Destroy both ipsets
        success, msg = destroy_ipsets_for_rule(rule_id)
        if not success:
            errors.append(f"ipset: {msg}")
        
        # Remove applied state
        self.db.delete_applied_state(rule_id)
        
        if errors:
            return False, "; ".join(errors)
        
        logger.info(f"Successfully removed rule: {rule.name}")
        return True, "Rule removed"
    
    def apply_all_rules(self) -> dict:
        """
        Apply all enabled routing rules.
        
        Returns:
            Dictionary with success/failed counts
        """
        rules = self.db.get_enabled_rules()
        results = {'success': 0, 'failed': 0, 'errors': []}
        
        for rule in rules:
            success, msg = self.apply_rule(rule)
            if success:
                results['success'] += 1
            else:
                results['failed'] += 1
                results['errors'].append(f"{rule.name}: {msg}")
        
        # Update dnsmasq config
        self._update_dnsmasq_config()
        
        logger.info(f"Applied {results['success']} rules, {results['failed']} failed")
        return results
    
    def _update_dnsmasq_config(self):
        """Update dnsmasq configuration with current rules (dual-stack)."""
        rules = self.db.get_enabled_rules()
        
        # Build config data with both IPv4 and IPv6 ipset names
        config_rules = []
        for rule in rules:
            config_rules.append({
                'name': rule.name,
                'domain': rule.domain,
                'ipset_name': get_ipset_name(rule.id),
                'ipset_name_v6': get_ipset_name_v6(rule.id),
                'enabled': rule.enabled
            })
        
        update_dnsmasq(config_rules, self.dnsmasq_config_path)
    
    def cleanup_all(self):
        """Remove all applied routing rules from the system."""
        logger.info("Cleaning up all routing rules...")
        
        # Get all rules and remove them
        rules = self.db.get_all_rules()
        for rule in rules:
            self.remove_rule(rule.id)
        
        # Additional cleanup for any orphaned resources
        cleanup_all_ipsets()
        cleanup_iptables()
        cleanup_dnsmasq(self.dnsmasq_config_path)
        
        # Clear all applied states
        self.db.clear_all_applied_states()
        
        logger.info("Cleanup complete")
    
    def get_rule_status(self, rule_id: int) -> dict:
        """
        Get detailed status of a rule.
        
        Args:
            rule_id: Rule ID
        
        Returns:
            Status dictionary
        """
        rule = self.db.get_rule_by_id(rule_id)
        if not rule:
            return {'error': 'Rule not found'}
        
        state = self.db.get_applied_state(rule_id)
        ipset_name = get_ipset_name(rule_id)
        
        # Get current IPs in ipset
        current_ips = list_ipset_entries(ipset_name)
        
        return {
            'rule_id': rule_id,
            'rule_name': rule.name,
            'enabled': rule.enabled,
            'status': state.status if state else 'not_applied',
            'ipset_name': ipset_name,
            'current_ips': current_ips,
            'applied_ips': json.loads(state.applied_ips) if state else [],
            'last_applied': state.last_applied if state else None
        }
