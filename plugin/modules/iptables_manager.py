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


def add_mangle_rules_dual_stack(ipset_name_v4: str, ipset_name_v6: str, fwmark: int, rule_id: int) -> tuple[bool, str]:
    """
    Add both iptables and ip6tables mangle rules for dual-stack support.
    
    Args:
        ipset_name_v4: Name of the IPv4 ipset
        ipset_name_v6: Name of the IPv6 ipset
        fwmark: Firewall mark value
        rule_id: Rule ID for tracking
    
    Returns:
        Tuple of (success, message)
    """
    errors = []
    
    # Add IPv4 rules
    success, msg = add_mangle_rule(ipset_name_v4, fwmark, rule_id)
    if not success:
        errors.append(f"IPv4: {msg}")
    
    # Add IPv6 rules
    success, msg = add_mangle_rule_v6(ipset_name_v6, fwmark, rule_id)
    if not success:
        errors.append(f"IPv6: {msg}")
    
    if errors:
        return False, "; ".join(errors)
    return True, "IPv4 and IPv6 mangle rules added"


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


def remove_mangle_rules_dual_stack(ipset_name_v4: str, ipset_name_v6: str, fwmark: int, rule_id: int) -> tuple[bool, str]:
    """
    Remove both iptables and ip6tables mangle rules.
    """
    errors = []
    
    success, msg = remove_mangle_rule(ipset_name_v4, fwmark, rule_id)
    if not success:
        errors.append(f"IPv4: {msg}")
    
    success, msg = remove_mangle_rule_v6(ipset_name_v6, fwmark, rule_id)
    if not success:
        errors.append(f"IPv6: {msg}")
    
    if errors:
        return False, "; ".join(errors)
    return True, "IPv4 and IPv6 mangle rules removed"


def list_plugin_rules() -> list[dict]:
    """
    List all iptables/ip6tables rules created by this plugin.
    
    Returns:
        List of rule dictionaries with chain, ipset, fwmark info
    """
    rules = []
    
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
                        'raw': line
                    })
    
    return rules


def cleanup_all_rules() -> int:
    """
    Remove all iptables and ip6tables rules created by this plugin.
    
    Returns:
        Number of rules removed
    """
    removed = 0
    
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
    
    logger.info(f"Cleaned up {removed} iptables/ip6tables rules")
    return removed
