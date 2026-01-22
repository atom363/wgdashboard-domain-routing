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
    
    success, output = run_command(cmd)
    
    if success:
        logger.info(f"Added default route to table {table}: via {gateway or interface}")
    else:
        logger.error(f"Failed to add route to table {table}: {output}")
    
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


def setup_wireguard_routing(fwmark: int, table: int, wg_interface: str) -> tuple[bool, str]:
    """
    Set up routing through a WireGuard interface for marked packets.
    
    Args:
        fwmark: Firewall mark value
        table: Routing table ID
        wg_interface: WireGuard interface name (e.g., "wg0")
    
    Returns:
        Tuple of (success, message)
    """
    # Verify interface exists
    success, _ = run_command(['ip', 'link', 'show', wg_interface], check=False)
    if not success:
        return False, f"WireGuard interface {wg_interface} not found"
    
    # Add ip rule
    success, msg = add_ip_rule(fwmark, table)
    if not success:
        return False, f"Failed to add ip rule: {msg}"
    
    # Add route via WireGuard interface
    success, msg = add_default_route_to_table(table, None, wg_interface)
    if not success:
        return False, f"Failed to add route: {msg}"
    
    return True, f"Routing via WireGuard interface {wg_interface}"


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
    
    # Remove ip rule
    success, msg = remove_ip_rule(fwmark, table)
    if not success:
        errors.append(f"rule: {msg}")
    
    # Flush routing table
    success, msg = flush_routing_table(table)
    if not success:
        errors.append(f"flush: {msg}")
    
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
