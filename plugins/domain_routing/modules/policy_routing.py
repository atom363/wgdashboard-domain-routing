"""
Policy routing manager for Domain Routing Plugin.
Handles ip rule and ip route configuration for fwmark-based routing.
"""

import subprocess
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


def run_command(cmd: list[str], check: bool = True) -> tuple[bool, str]:
    """
    Run a shell command and return success status and output.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check
        )
        # When check=False, we need to manually check returncode
        if result.returncode != 0:
            return False, result.stderr.strip() or f"Command failed with code {result.returncode}"
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.strip() or str(e)
    except Exception as e:
        return False, str(e)


def get_default_gateway() -> tuple[Optional[str], Optional[str]]:
    """
    Detect the default gateway IP and interface.
    
    Returns:
        Tuple of (gateway_ip, interface_name) or (None, None) if not found
    """
    success, output = run_command(['ip', 'route', 'show', 'default'])
    
    if not success or not output:
        logger.error("Failed to get default gateway")
        return None, None
    
    # Parse: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
    match = re.search(r'default via (\S+) dev (\S+)', output)
    if match:
        gateway_ip = match.group(1)
        interface = match.group(2)
        logger.debug(f"Default gateway: {gateway_ip} via {interface}")
        return gateway_ip, interface
    
    # Sometimes there's no gateway IP (direct route)
    match = re.search(r'default dev (\S+)', output)
    if match:
        interface = match.group(1)
        return None, interface
    
    return None, None


def ip_rule_exists(fwmark: int, table: int) -> bool:
    """
    Check if an ip rule for the given fwmark exists.
    
    Args:
        fwmark: Firewall mark value
        table: Routing table ID
    
    Returns:
        True if rule exists
    """
    success, output = run_command(['ip', 'rule', 'list'])
    
    if not success:
        return False
    
    # Look for rule with matching fwmark and table
    pattern = f"fwmark.*{hex(fwmark)}.*lookup {table}|fwmark.*{fwmark}.*lookup {table}"
    return bool(re.search(pattern, output))


def add_ip_rule(fwmark: int, table: int, priority: int = 100) -> tuple[bool, str]:
    """
    Add an ip rule to route marked packets to a specific table.
    
    Args:
        fwmark: Firewall mark to match
        table: Routing table to use
        priority: Rule priority (lower = higher priority)
    
    Returns:
        Tuple of (success, message)
    """
    if ip_rule_exists(fwmark, table):
        logger.debug(f"IP rule for fwmark {fwmark} already exists")
        return True, "Rule already exists"
    
    success, output = run_command([
        'ip', 'rule', 'add', 'fwmark', str(fwmark),
        'table', str(table), 'priority', str(priority)
    ])
    
    if success:
        logger.info(f"Added ip rule: fwmark {fwmark} -> table {table}")
    else:
        logger.error(f"Failed to add ip rule: {output}")
    
    return success, output


def remove_ip_rule(fwmark: int, table: int) -> tuple[bool, str]:
    """
    Remove an ip rule for marked packets.
    
    Args:
        fwmark: Firewall mark to match
        table: Routing table
    
    Returns:
        Tuple of (success, message)
    """
    if not ip_rule_exists(fwmark, table):
        return True, "Rule does not exist"
    
    success, output = run_command([
        'ip', 'rule', 'del', 'fwmark', str(fwmark), 'table', str(table)
    ])
    
    if success:
        logger.info(f"Removed ip rule for fwmark {fwmark}")
    
    return success, output


def add_default_route_to_table(table: int, gateway: Optional[str], interface: str) -> tuple[bool, str]:
    """
    Add a default route to a routing table.
    
    Args:
        table: Routing table ID
        gateway: Gateway IP (can be None for direct interface route)
        interface: Network interface
    
    Returns:
        Tuple of (success, message)
    """
    # First flush the table to ensure clean state
    run_command(['ip', 'route', 'flush', 'table', str(table)], check=False)
    
    if gateway:
        cmd = ['ip', 'route', 'add', 'default', 'via', gateway, 'dev', interface, 'table', str(table)]
    else:
        cmd = ['ip', 'route', 'add', 'default', 'dev', interface, 'table', str(table)]
        cmd6 = ['ip', '-6', 'route', 'add', 'default', 'dev', interface, 'table', str(table)]
    
    success, output = run_command(cmd)
    
    if success:
        logger.info(f"Added default route to table {table}: via {gateway or interface}")
    else:
        logger.error(f"Failed to add route to table {table}: {output}")

    if cmd6:
        success6, output6 = run_command(cmd6)
        if success6:
            logger.info(f"Added default v6 route to table {table}: dev {interface}")
        else:
            logger.error(f"Failed to add v6 route to table {table}: {output6}")
    
    return success, output


def flush_routing_table(table: int) -> tuple[bool, str]:
    """
    Flush all routes from a routing table.
    
    Args:
        table: Routing table ID
    
    Returns:
        Tuple of (success, message)
    """
    success, output = run_command(['ip', 'route', 'flush', 'table', str(table)])
    
    if success:
        logger.debug(f"Flushed routing table {table}")
    
    return success, output


def setup_default_gateway_routing(fwmark: int, table: int) -> tuple[bool, str]:
    """
    Set up routing through the default gateway for marked packets.
    This bypasses any VPN tunnel.
    
    Args:
        fwmark: Firewall mark value
        table: Routing table ID
    
    Returns:
        Tuple of (success, message)
    """
    gateway, interface = get_default_gateway()
    
    if not interface:
        return False, "Could not detect default gateway"
    
    # Add ip rule
    success, msg = add_ip_rule(fwmark, table)
    if not success:
        return False, f"Failed to add ip rule: {msg}"
    
    # Add route to table
    success, msg = add_default_route_to_table(table, gateway, interface)
    if not success:
        return False, f"Failed to add route: {msg}"
    
    return True, f"Routing via default gateway ({gateway or interface})"


def setup_wireguard_routing(fwmark: int, table: int, wg_interface: str, 
                            ipv4_gateway: Optional[str] = None, 
                            ipv6_gateway: Optional[str] = None) -> tuple[bool, str]:
    """
    Set up routing through a WireGuard peer for marked packets.
    
    Args:
        fwmark: Firewall mark value
        table: Routing table ID
        wg_interface: WireGuard interface name (e.g., "wg0")
        ipv4_gateway: IPv4 gateway (peer's first allowed IP)
        ipv6_gateway: IPv6 gateway (peer's second allowed IP)
    
    Returns:
        Tuple of (success, message)
    """
    # Verify interface exists
    success, _ = run_command(['ip', 'link', 'show', wg_interface], check=False)
    if not success:
        return False, f"WireGuard interface {wg_interface} not found"
    
    # Add ip rule for IPv4
    success, msg = add_ip_rule(fwmark, table)
    if not success:
        return False, f"Failed to add ip rule: {msg}"
    
    # Flush the table first
    run_command(['ip', 'route', 'flush', 'table', str(table)], check=False)
    
    routes_added = []
    
    # Add IPv4 route via peer gateway
    if ipv4_gateway:
        cmd = ['ip', 'route', 'add', 'default', 'via', ipv4_gateway, 'dev', wg_interface, 'table', str(table)]
        success, output = run_command(cmd)
        if success:
            logger.info(f"Added IPv4 route to table {table}: via {ipv4_gateway} dev {wg_interface}")
            routes_added.append(f"IPv4 via {ipv4_gateway}")
        else:
            logger.error(f"Failed to add IPv4 route: {output}")
    
    # Add IPv6 route via peer gateway
    if ipv6_gateway:
        # Add ip rule for IPv6 if not exists
        success6, _ = run_command(['ip', '-6', 'rule', 'list'])
        if success6:
            # Check if IPv6 rule exists
            success6, output = run_command(['ip', '-6', 'rule', 'add', 'fwmark', str(fwmark), 'table', str(table)], check=False)
            if success6:
                logger.info(f"Added IPv6 rule: fwmark {fwmark} -> table {table}")
        
        cmd = ['ip', '-6', 'route', 'add', 'default', 'via', ipv6_gateway, 'dev', wg_interface, 'table', str(table)]
        success, output = run_command(cmd, check=False)
        if success:
            logger.info(f"Added IPv6 route to table {table}: via {ipv6_gateway} dev {wg_interface}")
            routes_added.append(f"IPv6 via {ipv6_gateway}")
        else:
            logger.warning(f"Failed to add IPv6 route: {output}")
    
    # Fallback: if no gateways provided, just route via interface
    if not ipv4_gateway and not ipv6_gateway:
        success, msg = add_default_route_to_table(table, None, wg_interface)
        if not success:
            return False, f"Failed to add route: {msg}"
        routes_added.append(f"dev {wg_interface}")
    
    if not routes_added:
        return False, "No routes were added"
    
    return True, f"Routing via WireGuard: {', '.join(routes_added)}"


def cleanup_routing(fwmark: int, table: int) -> tuple[bool, str]:
    """
    Clean up routing configuration for a rule.
    
    Args:
        fwmark: Firewall mark value
        table: Routing table ID
    
    Returns:
        Tuple of (success, message)
    """
    errors = []
    
    # Remove IPv4 ip rule
    success, msg = remove_ip_rule(fwmark, table)
    if not success:
        errors.append(f"rule: {msg}")
    
    # Remove IPv6 ip rule (if exists)
    run_command(['ip', '-6', 'rule', 'del', 'fwmark', str(fwmark), 'table', str(table)], check=False)
    
    # Flush IPv4 routing table
    success, msg = flush_routing_table(table)
    if not success:
        errors.append(f"flush: {msg}")
    
    # Flush IPv6 routing table
    run_command(['ip', '-6', 'route', 'flush', 'table', str(table)], check=False)
    
    if errors:
        return False, "; ".join(errors)
    
    return True, "Routing cleaned up"


def list_plugin_rules() -> list[dict]:
    """
    List all ip rules that might be created by this plugin.
    
    Returns:
        List of rule info dictionaries
    """
    success, output = run_command(['ip', 'rule', 'list'])
    
    if not success:
        return []
    
    rules = []
    for line in output.split('\n'):
        # Look for fwmark rules with tables >= 100
        match = re.search(r'fwmark\s+(0x[0-9a-f]+|\d+).*lookup\s+(\d+)', line)
        if match:
            fwmark = match.group(1)
            if fwmark.startswith('0x'):
                fwmark = int(fwmark, 16)
            else:
                fwmark = int(fwmark)
            table = int(match.group(2))
            
            # Plugin uses tables 100-999
            if 100 <= table <= 999:
                rules.append({
                    'fwmark': fwmark,
                    'table': table,
                    'raw': line
                })
    
    return rules


# Static Route Functions

def is_ipv6(destination: str) -> bool:
    """Check if a destination is IPv6."""
    return ':' in destination


def static_route_exists(destination: str, gateway: Optional[str], interface: Optional[str]) -> bool:
    """
    Check if a static route already exists.
    
    Args:
        destination: Destination network (e.g., "192.168.1.0/24")
        gateway: Gateway IP (optional)
        interface: Network interface (optional)
    
    Returns:
        True if route exists
    """
    ip_version = '-6' if is_ipv6(destination) else '-4'
    success, output = run_command(['ip', ip_version, 'route', 'show', destination], check=False)
    
    if not success or not output:
        return False
    
    # Check if the route matches our parameters
    if gateway and gateway not in output:
        return False
    if interface and f"dev {interface}" not in output:
        return False
    
    return True


def add_static_route(destination: str, gateway: Optional[str], interface: Optional[str]) -> tuple[bool, str]:
    """
    Add a static route to the main routing table.
    
    Args:
        destination: Destination network (e.g., "192.168.1.0/24" or "2001:db8::/64")
        gateway: Gateway IP (optional, uses interface if not set)
        interface: Network interface (optional)
    
    Returns:
        Tuple of (success, message)
    """
    if static_route_exists(destination, gateway, interface):
        logger.debug(f"Static route to {destination} already exists")
        return True, "Route already exists"
    
    ip_version = '-6' if is_ipv6(destination) else '-4'
    cmd = ['ip', ip_version, 'route', 'add', destination]
    
    if gateway:
        cmd.extend(['via', gateway])
    if interface:
        cmd.extend(['dev', interface])
    
    success, output = run_command(cmd)
    
    if success:
        route_desc = f"{destination}"
        if gateway:
            route_desc += f" via {gateway}"
        if interface:
            route_desc += f" dev {interface}"
        logger.info(f"Added static route: {route_desc}")
        return True, f"Route added: {route_desc}"
    else:
        logger.error(f"Failed to add static route to {destination}: {output}")
        return False, output


def remove_static_route(destination: str, gateway: Optional[str], interface: Optional[str]) -> tuple[bool, str]:
    """
    Remove a static route from the main routing table.
    
    Args:
        destination: Destination network (e.g., "192.168.1.0/24")
        gateway: Gateway IP (optional)
        interface: Network interface (optional)
    
    Returns:
        Tuple of (success, message)
    """
    ip_version = '-6' if is_ipv6(destination) else '-4'
    cmd = ['ip', ip_version, 'route', 'del', destination]
    
    if gateway:
        cmd.extend(['via', gateway])
    if interface:
        cmd.extend(['dev', interface])
    
    success, output = run_command(cmd, check=False)
    
    if success:
        logger.info(f"Removed static route to {destination}")
        return True, f"Route to {destination} removed"
    
    # Route might not exist, which is fine
    if "No such process" in output or "not in table" in output:
        return True, "Route did not exist"
    
    return False, output


def add_static_route_via_wireguard(destination: str, wg_interface: str,
                                   ipv4_gateway: Optional[str] = None,
                                   ipv6_gateway: Optional[str] = None) -> tuple[bool, str]:
    """
    Add a static route through a WireGuard interface.
    
    Args:
        destination: Destination network
        wg_interface: WireGuard interface name
        ipv4_gateway: IPv4 gateway (for IPv4 destinations)
        ipv6_gateway: IPv6 gateway (for IPv6 destinations)
    
    Returns:
        Tuple of (success, message)
    """
    # Determine which gateway to use based on destination
    if is_ipv6(destination):
        gateway = ipv6_gateway
    else:
        gateway = ipv4_gateway
    
    return add_static_route(destination, gateway, wg_interface)


def list_static_routes() -> list[dict]:
    """
    List all static routes in the main routing table.
    
    Returns:
        List of route dictionaries
    """
    routes = []
    
    # Get IPv4 routes
    success, output = run_command(['ip', '-4', 'route', 'show'], check=False)
    if success:
        for line in output.split('\n'):
            # Parse: "192.168.10.0/24 via 192.168.1.1 dev eth0"
            # or: "192.168.10.0/24 dev wg0"
            match = re.match(r'(\S+)\s+(?:via\s+(\S+)\s+)?dev\s+(\S+)', line)
            if match:
                routes.append({
                    'destination': match.group(1),
                    'gateway': match.group(2),
                    'interface': match.group(3),
                    'family': 'inet'
                })
    
    # Get IPv6 routes
    success, output = run_command(['ip', '-6', 'route', 'show'], check=False)
    if success:
        for line in output.split('\n'):
            match = re.match(r'(\S+)\s+(?:via\s+(\S+)\s+)?dev\s+(\S+)', line)
            if match:
                routes.append({
                    'destination': match.group(1),
                    'gateway': match.group(2),
                    'interface': match.group(3),
                    'family': 'inet6'
                })
    
    return routes
