"""
iptables manager for Domain Routing Plugin.
Handles creation and removal of mangle rules for packet marking.
"""

import subprocess
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Comment prefix for identifying plugin-managed rules
COMMENT_PREFIX = "wgdomain"


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


def get_comment(rule_id: int) -> str:
    """Generate comment for a rule."""
    return f"{COMMENT_PREFIX}_{rule_id}"


def rule_exists(chain: str, ipset_name: str, fwmark: int, rule_id: int, use_ip6tables: bool = False) -> bool:
    """
    Check if a mangle rule already exists.
    
    Args:
        chain: iptables chain (OUTPUT or PREROUTING)
        ipset_name: Name of the ipset to match
        fwmark: Firewall mark to set
        rule_id: Rule ID for comment
        use_ip6tables: Use ip6tables instead of iptables
    
    Returns:
        True if rule exists
    """
    cmd_base = 'ip6tables' if use_ip6tables else 'iptables'
    success, _ = run_command([
        cmd_base, '-t', 'mangle', '-C', chain,
        '-m', 'set', '--match-set', ipset_name, 'dst',
        '-j', 'MARK', '--set-mark', str(fwmark),
        '-m', 'comment', '--comment', get_comment(rule_id)
    ], check=False)
    
    return success


def _add_mangle_rule_single(ipset_name: str, fwmark: int, rule_id: int, use_ip6tables: bool = False) -> tuple[bool, str]:
    """
    Add iptables/ip6tables mangle rules to mark packets destined for ipset.
    
    Args:
        ipset_name: Name of the ipset to match against
        fwmark: Firewall mark value to set on matching packets
        rule_id: Rule ID for tracking
        use_ip6tables: Use ip6tables instead of iptables
    
    Returns:
        Tuple of (success, message)
    """
    cmd_base = 'ip6tables' if use_ip6tables else 'iptables'
    proto = 'IPv6' if use_ip6tables else 'IPv4'
    
    logger.info(f"Adding {proto} mangle rules for ipset={ipset_name}, fwmark={fwmark}, rule_id={rule_id}")
    errors = []
    
    for chain in ['OUTPUT', 'PREROUTING']:
        if rule_exists(chain, ipset_name, fwmark, rule_id, use_ip6tables):
            logger.debug(f"{proto} rule already exists in {chain} for {ipset_name}")
            continue
        
        cmd = [
            cmd_base, '-t', 'mangle', '-A', chain,
            '-m', 'set', '--match-set', ipset_name, 'dst',
            '-j', 'MARK', '--set-mark', str(fwmark),
            '-m', 'comment', '--comment', get_comment(rule_id)
        ]
        logger.info(f"Running: {' '.join(cmd)}")
        
        success, output = run_command(cmd)
        
        if success:
            logger.info(f"Added {proto} mangle rule in {chain} for ipset {ipset_name} with mark {fwmark}")
        else:
            errors.append(f"{chain}: {output}")
            logger.error(f"Failed to add {proto} mangle rule in {chain}: {output}")
    
    if errors:
        return False, "; ".join(errors)
    return True, f"{proto} mangle rules added"


def add_mangle_rule(ipset_name: str, fwmark: int, rule_id: int) -> tuple[bool, str]:
    """
    Add iptables mangle rules (IPv4 only) to mark packets destined for ipset.
    Creates rules in both OUTPUT (local traffic) and PREROUTING (forwarded traffic) chains.
    
    Args:
        ipset_name: Name of the ipset to match against
        fwmark: Firewall mark value to set on matching packets
        rule_id: Rule ID for tracking
    
    Returns:
        Tuple of (success, message)
    """
    return _add_mangle_rule_single(ipset_name, fwmark, rule_id, use_ip6tables=False)


def add_mangle_rule_v6(ipset_name: str, fwmark: int, rule_id: int) -> tuple[bool, str]:
    """
    Add ip6tables mangle rules (IPv6 only) to mark packets destined for ipset.
    
    Args:
        ipset_name: Name of the IPv6 ipset to match against
        fwmark: Firewall mark value to set on matching packets
        rule_id: Rule ID for tracking
    
    Returns:
        Tuple of (success, message)
    """
    return _add_mangle_rule_single(ipset_name, fwmark, rule_id, use_ip6tables=True)


def block_rule_exists(chain: str, ipset_name: str, rule_id: int, use_ip6tables: bool = False, is_tcp: bool = False) -> bool:
    """
    Check if a block rule already exists in the filter table.
    
    Args:
        chain: iptables chain (OUTPUT or FORWARD)
        ipset_name: Name of the ipset to match
        rule_id: Rule ID for comment
        use_ip6tables: Use ip6tables instead of iptables
        is_tcp: Check for TCP-specific rule (REJECT) vs generic DROP rule
    
    Returns:
        True if rule exists
    """
    cmd_base = 'ip6tables' if use_ip6tables else 'iptables'
    
    if is_tcp:
        # Check for TCP REJECT rule in filter table
        success, _ = run_command([
            cmd_base, '-t', 'filter', '-C', chain,
            '-m', 'set', '--match-set', ipset_name, 'dst',
            '-p', 'tcp',
            '-j', 'REJECT', '--reject-with', 'tcp-reset',
            '-m', 'comment', '--comment', get_comment(rule_id)
        ], check=False)
    else:
        # Check for generic DROP rule in filter table
        success, _ = run_command([
            cmd_base, '-t', 'filter', '-C', chain,
            '-m', 'set', '--match-set', ipset_name, 'dst',
            '-j', 'DROP',
            '-m', 'comment', '--comment', get_comment(rule_id)
        ], check=False)
    
    return success


def add_block_rule_single(ipset_name: str, rule_id: int, use_ip6tables: bool = False) -> tuple[bool, str]:
    """
    Add iptables rules to block traffic in the filter table.
    
    TCP traffic is rejected with RST, other protocols are dropped.
    Requires two rules per chain:
    1. TCP traffic: -p tcp -j REJECT --reject-with tcp-reset
    2. All other traffic: -j DROP
    
    Note: Uses filter table (not mangle) because REJECT target is not available in mangle.
    
    Args:
        ipset_name: Name of the ipset to match against
        rule_id: Rule ID for tracking
        use_ip6tables: Use ip6tables instead of iptables
    
    Returns:
        Tuple of (success, message)
    """
    cmd_base = 'ip6tables' if use_ip6tables else 'iptables'
    proto = 'IPv6' if use_ip6tables else 'IPv4'
    
    logger.info(f"Adding {proto} block rules for ipset={ipset_name}, rule_id={rule_id}")
    errors = []
    
    # Use OUTPUT and FORWARD chains in filter table (PREROUTING is not available in filter)
    for chain in ['OUTPUT', 'FORWARD']:
        # Add TCP REJECT rule first (more specific)
        if not block_rule_exists(chain, ipset_name, rule_id, use_ip6tables, is_tcp=True):
            cmd = [
                cmd_base, '-t', 'filter', '-A', chain,
                '-m', 'set', '--match-set', ipset_name, 'dst',
                '-p', 'tcp',
                '-j', 'REJECT', '--reject-with', 'tcp-reset',
                '-m', 'comment', '--comment', get_comment(rule_id)
            ]
            logger.info(f"Running: {' '.join(cmd)}")
            
            success, output = run_command(cmd)
            if success:
                logger.info(f"Added {proto} TCP REJECT rule in {chain} for ipset {ipset_name}")
            else:
                errors.append(f"{chain} TCP: {output}")
                logger.error(f"Failed to add {proto} TCP REJECT rule in {chain}: {output}")
        else:
            logger.debug(f"{proto} TCP REJECT rule already exists in {chain} for {ipset_name}")
        
        # Add generic DROP rule
        if not block_rule_exists(chain, ipset_name, rule_id, use_ip6tables, is_tcp=False):
            cmd = [
                cmd_base, '-t', 'filter', '-A', chain,
                '-m', 'set', '--match-set', ipset_name, 'dst',
                '-j', 'DROP',
                '-m', 'comment', '--comment', get_comment(rule_id)
            ]
            logger.info(f"Running: {' '.join(cmd)}")
            
            success, output = run_command(cmd)
            if success:
                logger.info(f"Added {proto} DROP rule in {chain} for ipset {ipset_name}")
            else:
                errors.append(f"{chain} DROP: {output}")
                logger.error(f"Failed to add {proto} DROP rule in {chain}: {output}")
        else:
            logger.debug(f"{proto} DROP rule already exists in {chain} for {ipset_name}")
    
    if errors:
        return False, "; ".join(errors)
    return True, f"{proto} block rules added"


def add_block_rule(ipset_name: str, rule_id: int) -> tuple[bool, str]:
    """Add IPv4 block rules."""
    return add_block_rule_single(ipset_name, rule_id, use_ip6tables=False)


def add_block_rule_v6(ipset_name: str, rule_id: int) -> tuple[bool, str]:
    """Add IPv6 block rules."""
    return add_block_rule_single(ipset_name, rule_id, use_ip6tables=True)


def add_mangle_rules_dual_stack(
    ipset_name_v4: str, 
    ipset_name_v6: str, 
    fwmark: int, 
    rule_id: int,
    ipv4_action: str = "forward",
    ipv6_action: str = "forward"
) -> tuple[bool, str]:
    """
    Add both iptables and ip6tables rules for dual-stack support.
    
    Args:
        ipset_name_v4: Name of the IPv4 ipset
        ipset_name_v6: Name of the IPv6 ipset
        fwmark: Firewall mark value (for forward action)
        rule_id: Rule ID for tracking
        ipv4_action: "forward" or "block"
        ipv6_action: "forward" or "block"
    
    Returns:
        Tuple of (success, message)
    """
    errors = []
    
    # Handle IPv4
    if ipv4_action == "forward":
        success, msg = add_mangle_rule(ipset_name_v4, fwmark, rule_id)
        if not success:
            errors.append(f"IPv4: {msg}")
    else:  # block
        success, msg = add_block_rule(ipset_name_v4, rule_id)
        if not success:
            errors.append(f"IPv4: {msg}")
    
    # Handle IPv6
    if ipv6_action == "forward":
        success, msg = add_mangle_rule_v6(ipset_name_v6, fwmark, rule_id)
        if not success:
            errors.append(f"IPv6: {msg}")
    else:  # block
        success, msg = add_block_rule_v6(ipset_name_v6, rule_id)
        if not success:
            errors.append(f"IPv6: {msg}")
    
    if errors:
        return False, "; ".join(errors)
    return True, "IPv4 and IPv6 rules added"


def _remove_mangle_rule_single(ipset_name: str, fwmark: int, rule_id: int, use_ip6tables: bool = False) -> tuple[bool, str]:
    """
    Remove iptables/ip6tables mangle rules for a specific ipset.
    """
    cmd_base = 'ip6tables' if use_ip6tables else 'iptables'
    proto = 'IPv6' if use_ip6tables else 'IPv4'
    errors = []
    
    for chain in ['OUTPUT', 'PREROUTING']:
        if not rule_exists(chain, ipset_name, fwmark, rule_id, use_ip6tables):
            continue
        
        success, output = run_command([
            cmd_base, '-t', 'mangle', '-D', chain,
            '-m', 'set', '--match-set', ipset_name, 'dst',
            '-j', 'MARK', '--set-mark', str(fwmark),
            '-m', 'comment', '--comment', get_comment(rule_id)
        ])
        
        if success:
            logger.info(f"Removed {proto} mangle rule from {chain} for ipset {ipset_name}")
        else:
            errors.append(f"{chain}: {output}")
    
    if errors:
        return False, "; ".join(errors)
    return True, f"{proto} mangle rules removed"


def remove_mangle_rule(ipset_name: str, fwmark: int, rule_id: int) -> tuple[bool, str]:
    """
    Remove iptables mangle rules (IPv4 only) for a specific ipset.
    """
    return _remove_mangle_rule_single(ipset_name, fwmark, rule_id, use_ip6tables=False)


def remove_mangle_rule_v6(ipset_name: str, fwmark: int, rule_id: int) -> tuple[bool, str]:
    """
    Remove ip6tables mangle rules (IPv6 only) for a specific ipset.
    """
    return _remove_mangle_rule_single(ipset_name, fwmark, rule_id, use_ip6tables=True)


def _remove_block_rule_single(ipset_name: str, rule_id: int, use_ip6tables: bool = False) -> tuple[bool, str]:
    """
    Remove iptables/ip6tables block rules for a specific ipset.
    Removes both TCP REJECT and generic DROP rules from the filter table.
    """
    cmd_base = 'ip6tables' if use_ip6tables else 'iptables'
    proto = 'IPv6' if use_ip6tables else 'IPv4'
    errors = []
    
    # Use OUTPUT and FORWARD chains in filter table
    for chain in ['OUTPUT', 'FORWARD']:
        # Remove TCP REJECT rule
        if block_rule_exists(chain, ipset_name, rule_id, use_ip6tables, is_tcp=True):
            success, output = run_command([
                cmd_base, '-t', 'filter', '-D', chain,
                '-m', 'set', '--match-set', ipset_name, 'dst',
                '-p', 'tcp',
                '-j', 'REJECT', '--reject-with', 'tcp-reset',
                '-m', 'comment', '--comment', get_comment(rule_id)
            ])
            if success:
                logger.info(f"Removed {proto} TCP REJECT rule from {chain} for ipset {ipset_name}")
            else:
                errors.append(f"{chain} TCP: {output}")
        
        # Remove generic DROP rule
        if block_rule_exists(chain, ipset_name, rule_id, use_ip6tables, is_tcp=False):
            success, output = run_command([
                cmd_base, '-t', 'filter', '-D', chain,
                '-m', 'set', '--match-set', ipset_name, 'dst',
                '-j', 'DROP',
                '-m', 'comment', '--comment', get_comment(rule_id)
            ])
            if success:
                logger.info(f"Removed {proto} DROP rule from {chain} for ipset {ipset_name}")
            else:
                errors.append(f"{chain} DROP: {output}")
    
    if errors:
        return False, "; ".join(errors)
    return True, f"{proto} block rules removed"


def remove_block_rule(ipset_name: str, rule_id: int) -> tuple[bool, str]:
    """Remove IPv4 block rules."""
    return _remove_block_rule_single(ipset_name, rule_id, use_ip6tables=False)


def remove_block_rule_v6(ipset_name: str, rule_id: int) -> tuple[bool, str]:
    """Remove IPv6 block rules."""
    return _remove_block_rule_single(ipset_name, rule_id, use_ip6tables=True)


def remove_mangle_rules_dual_stack(ipset_name_v4: str, ipset_name_v6: str, fwmark: int, rule_id: int) -> tuple[bool, str]:
    """
    Remove both iptables and ip6tables rules (both forward mangle rules and block rules).
    """
    errors = []
    
    # Remove IPv4 mangle (forward) rules
    success, msg = remove_mangle_rule(ipset_name_v4, fwmark, rule_id)
    if not success:
        errors.append(f"IPv4 mangle: {msg}")
    
    # Remove IPv4 block rules
    success, msg = remove_block_rule(ipset_name_v4, rule_id)
    if not success:
        errors.append(f"IPv4 block: {msg}")
    
    # Remove IPv6 mangle (forward) rules
    success, msg = remove_mangle_rule_v6(ipset_name_v6, fwmark, rule_id)
    if not success:
        errors.append(f"IPv6 mangle: {msg}")
    
    # Remove IPv6 block rules
    success, msg = remove_block_rule_v6(ipset_name_v6, rule_id)
    if not success:
        errors.append(f"IPv6 block: {msg}")
    
    if errors:
        return False, "; ".join(errors)
    return True, "IPv4 and IPv6 rules removed"


def list_plugin_rules() -> list[dict]:
    """
    List all iptables/ip6tables rules created by this plugin.
    
    Returns:
        List of rule dictionaries with chain, ipset, fwmark info
    """
    rules = []
    
    # Check mangle table (forward rules)
    for cmd_base, proto in [('iptables', 'IPv4'), ('ip6tables', 'IPv6')]:
        for chain in ['OUTPUT', 'PREROUTING']:
            success, output = run_command([
                cmd_base, '-t', 'mangle', '-L', chain, '-n', '-v', '--line-numbers'
            ], check=False)
            
            if not success:
                continue
            
            for line in output.split('\n'):
                if COMMENT_PREFIX in line:
                    rules.append({
                        'chain': chain,
                        'protocol': proto,
                        'table': 'mangle',
                        'raw': line
                    })
    
    # Check filter table (block rules)
    for cmd_base, proto in [('iptables', 'IPv4'), ('ip6tables', 'IPv6')]:
        for chain in ['OUTPUT', 'FORWARD']:
            success, output = run_command([
                cmd_base, '-t', 'filter', '-L', chain, '-n', '-v', '--line-numbers'
            ], check=False)
            
            if not success:
                continue
            
            for line in output.split('\n'):
                if COMMENT_PREFIX in line:
                    rules.append({
                        'chain': chain,
                        'protocol': proto,
                        'table': 'filter',
                        'raw': line
                    })
    
    return rules


def cleanup_all_rules() -> int:
    """
    Remove all iptables and ip6tables rules created by this plugin.
    Cleans up both mangle table (forward rules) and filter table (block rules).
    
    Returns:
        Number of rules removed
    """
    removed = 0
    
    # Clean up mangle table (forward rules)
    for cmd_base in ['iptables', 'ip6tables']:
        for chain in ['OUTPUT', 'PREROUTING']:
            # Get all rules with line numbers
            success, output = run_command([
                cmd_base, '-t', 'mangle', '-L', chain, '-n', '--line-numbers'
            ], check=False)
            
            if not success:
                continue
            
            # Find rules with our comment and delete them (in reverse order to preserve line numbers)
            lines_to_delete = []
            for line in output.split('\n'):
                if COMMENT_PREFIX in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        lines_to_delete.append(int(parts[0]))
            
            # Delete in reverse order
            for line_num in sorted(lines_to_delete, reverse=True):
                success, _ = run_command([
                    cmd_base, '-t', 'mangle', '-D', chain, str(line_num)
                ], check=False)
                if success:
                    removed += 1
    
    # Clean up filter table (block rules)
    for cmd_base in ['iptables', 'ip6tables']:
        for chain in ['OUTPUT', 'FORWARD']:
            # Get all rules with line numbers
            success, output = run_command([
                cmd_base, '-t', 'filter', '-L', chain, '-n', '--line-numbers'
            ], check=False)
            
            if not success:
                continue
            
            # Find rules with our comment and delete them (in reverse order to preserve line numbers)
            lines_to_delete = []
            for line in output.split('\n'):
                if COMMENT_PREFIX in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        lines_to_delete.append(int(parts[0]))
            
            # Delete in reverse order
            for line_num in sorted(lines_to_delete, reverse=True):
                success, _ = run_command([
                    cmd_base, '-t', 'filter', '-D', chain, str(line_num)
                ], check=False)
                if success:
                    removed += 1
    
    logger.info(f"Cleaned up {removed} iptables/ip6tables rules")
    return removed
