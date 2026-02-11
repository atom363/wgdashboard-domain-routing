"""
ipset manager for Domain Routing Plugin.
Handles creation, destruction, and management of ipsets.
"""

import subprocess
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Prefix for all ipsets created by this plugin
IPSET_PREFIX = "wg_domain_"


def run_command(cmd: list[str], check: bool = True) -> tuple[bool, str]:
    """
    Run a shell command and return success status and output.
    
    Args:
        cmd: Command and arguments as list
        check: Whether to raise on non-zero exit
    
    Returns:
        Tuple of (success, output/error message)
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


def get_ipset_name(rule_id: int) -> str:
    """Generate IPv4 ipset name for a rule."""
    return f"{IPSET_PREFIX}{rule_id}"


def get_ipset_name_v6(rule_id: int) -> str:
    """Generate IPv6 ipset name for a rule."""
    return f"{IPSET_PREFIX}{rule_id}_v6"


def is_ipv6(ip: str) -> bool:
    """Check if an IP address is IPv6."""
    return ':' in ip


def ipset_exists(name: str) -> bool:
    """Check if an ipset exists."""
    success, _ = run_command(['ipset', 'list', '-n', name], check=False)
    return success


def create_ipset(name: str, family: str = 'inet') -> tuple[bool, str]:
    """
    Create a new ipset for storing IP addresses.
    
    Args:
        name: Name of the ipset to create
        family: 'inet' for IPv4, 'inet6' for IPv6
    
    Returns:
        Tuple of (success, message)
    """
    logger.info(f"Creating ipset: {name} (family={family})")
    
    if ipset_exists(name):
        logger.debug(f"ipset {name} already exists")
        return True, "ipset already exists"
    
    cmd = [
        'ipset', 'create', name, 'hash:ip',
        'family', family,
        'timeout', '0'  # No automatic timeout
    ]
    logger.info(f"Running: {' '.join(cmd)}")
    
    success, output = run_command(cmd)
    
    if success:
        logger.info(f"Created ipset: {name}")
    else:
        logger.error(f"Failed to create ipset {name}: {output}")
    
    return success, output


def create_ipsets_for_rule(rule_id: int) -> tuple[bool, str]:
    """
    Create both IPv4 and IPv6 ipsets for a rule.
    
    Args:
        rule_id: Rule ID
    
    Returns:
        Tuple of (success, message)
    """
    errors = []
    
    # Create IPv4 ipset
    ipset_v4 = get_ipset_name(rule_id)
    success, msg = create_ipset(ipset_v4, 'inet')
    if not success:
        errors.append(f"IPv4: {msg}")
    
    # Create IPv6 ipset
    ipset_v6 = get_ipset_name_v6(rule_id)
    success, msg = create_ipset(ipset_v6, 'inet6')
    if not success:
        errors.append(f"IPv6: {msg}")
    
    if errors:
        return False, "; ".join(errors)
    return True, "IPv4 and IPv6 ipsets created"


def destroy_ipsets_for_rule(rule_id: int) -> tuple[bool, str]:
    """
    Destroy both IPv4 and IPv6 ipsets for a rule.
    
    Args:
        rule_id: Rule ID
    
    Returns:
        Tuple of (success, message)
    """
    errors = []
    
    # Destroy IPv4 ipset
    ipset_v4 = get_ipset_name(rule_id)
    success, msg = destroy_ipset(ipset_v4)
    if not success:
        errors.append(f"IPv4: {msg}")
    
    # Destroy IPv6 ipset
    ipset_v6 = get_ipset_name_v6(rule_id)
    success, msg = destroy_ipset(ipset_v6)
    if not success:
        errors.append(f"IPv6: {msg}")
    
    if errors:
        return False, "; ".join(errors)
    return True, "IPv4 and IPv6 ipsets destroyed"


def destroy_ipset(name: str) -> tuple[bool, str]:
    """
    Destroy an ipset.
    
    Args:
        name: Name of the ipset to destroy
    
    Returns:
        Tuple of (success, message)
    """
    if not ipset_exists(name):
        return True, "ipset does not exist"
    
    # Flush the ipset first
    flush_ipset(name)
    
    success, output = run_command(['ipset', 'destroy', name])
    
    if success:
        logger.info(f"Destroyed ipset: {name}")
    else:
        logger.error(f"Failed to destroy ipset {name}: {output}")
    
    return success, output


def flush_ipset(name: str) -> tuple[bool, str]:
    """
    Flush all entries from an ipset.
    
    Args:
        name: Name of the ipset to flush
    
    Returns:
        Tuple of (success, message)
    """
    if not ipset_exists(name):
        return True, "ipset does not exist"
    
    success, output = run_command(['ipset', 'flush', name])
    
    if success:
        logger.debug(f"Flushed ipset: {name}")
    
    return success, output


def add_ip_to_ipset(name: str, ip: str) -> tuple[bool, str]:
    """
    Add an IP address to an ipset.
    
    Args:
        name: Name of the ipset
        ip: IP address to add
    
    Returns:
        Tuple of (success, message)
    """
    if not ipset_exists(name):
        return False, f"ipset {name} does not exist"
    
    # Use -exist flag to ignore if already exists
    success, output = run_command([
        'ipset', 'add', name, ip, '-exist'
    ])
    
    if success:
        logger.debug(f"Added {ip} to ipset {name}")
    
    return success, output


def add_ip_to_rule_ipset(rule_id: int, ip: str) -> tuple[bool, str]:
    """
    Add an IP to the appropriate ipset (IPv4 or IPv6) for a rule.
    
    Args:
        rule_id: Rule ID
        ip: IP address to add
    
    Returns:
        Tuple of (success, message)
    """
    if is_ipv6(ip):
        ipset_name = get_ipset_name_v6(rule_id)
    else:
        ipset_name = get_ipset_name(rule_id)
    
    return add_ip_to_ipset(ipset_name, ip)


def remove_ip_from_ipset(name: str, ip: str) -> tuple[bool, str]:
    """
    Remove an IP address from an ipset.
    
    Args:
        name: Name of the ipset
        ip: IP address to remove
    
    Returns:
        Tuple of (success, message)
    """
    if not ipset_exists(name):
        return True, "ipset does not exist"
    
    success, output = run_command([
        'ipset', 'del', name, ip, '-exist'
    ])
    
    return success, output


def list_ipset_entries(name: str) -> list[str]:
    """
    List all IP addresses in an ipset.
    
    Args:
        name: Name of the ipset
    
    Returns:
        List of IP addresses
    """
    if not ipset_exists(name):
        return []
    
    success, output = run_command(['ipset', 'list', name])
    
    if not success:
        return []
    
    # Parse output to extract IPs (they come after "Members:" line)
    ips = []
    in_members = False
    for line in output.split('\n'):
        if line.startswith('Members:'):
            in_members = True
            continue
        if in_members and line.strip():
            # IP might have timeout info, extract just the IP
            ip = line.strip().split()[0]
            ips.append(ip)
    
    return ips


def list_plugin_ipsets() -> list[str]:
    """
    List all ipsets created by this plugin.
    
    Returns:
        List of ipset names
    """
    success, output = run_command(['ipset', 'list', '-n'])
    
    if not success:
        return []
    
    return [
        name for name in output.split('\n')
        if name.startswith(IPSET_PREFIX)
    ]


def cleanup_all_ipsets() -> int:
    """
    Remove all ipsets created by this plugin.
    
    Returns:
        Number of ipsets removed
    """
    ipsets = list_plugin_ipsets()
    removed = 0
    
    for name in ipsets:
        success, _ = destroy_ipset(name)
        if success:
            removed += 1
    
    logger.info(f"Cleaned up {removed} ipsets")
    return removed
