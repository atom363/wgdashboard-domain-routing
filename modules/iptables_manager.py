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
        return True, result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.strip() or str(e)
    except Exception as e:
        return False, str(e)


def get_comment(rule_id: int) -> str:
    """Generate comment for a rule."""
    return f"{COMMENT_PREFIX}_{rule_id}"


def rule_exists(chain: str, ipset_name: str, fwmark: int, rule_id: int) -> bool:
    """
    Check if a mangle rule already exists.
    
    Args:
        chain: iptables chain (OUTPUT or PREROUTING)
        ipset_name: Name of the ipset to match
        fwmark: Firewall mark to set
        rule_id: Rule ID for comment
    
    Returns:
        True if rule exists
    """
    success, _ = run_command([
        'iptables', '-t', 'mangle', '-C', chain,
        '-m', 'set', '--match-set', ipset_name, 'dst',
        '-j', 'MARK', '--set-mark', str(fwmark),
        '-m', 'comment', '--comment', get_comment(rule_id)
    ], check=False)
    
    return success


def add_mangle_rule(ipset_name: str, fwmark: int, rule_id: int) -> tuple[bool, str]:
    """
    Add iptables mangle rules to mark packets destined for ipset.
    Creates rules in both OUTPUT (local traffic) and PREROUTING (forwarded traffic) chains.
    
    Args:
        ipset_name: Name of the ipset to match against
        fwmark: Firewall mark value to set on matching packets
        rule_id: Rule ID for tracking
    
    Returns:
        Tuple of (success, message)
    """
    errors = []
    
    for chain in ['OUTPUT', 'PREROUTING']:
        if rule_exists(chain, ipset_name, fwmark, rule_id):
            logger.debug(f"Rule already exists in {chain} for {ipset_name}")
            continue
        
        success, output = run_command([
            'iptables', '-t', 'mangle', '-A', chain,
            '-m', 'set', '--match-set', ipset_name, 'dst',
            '-j', 'MARK', '--set-mark', str(fwmark),
            '-m', 'comment', '--comment', get_comment(rule_id)
        ])
        
        if success:
            logger.info(f"Added mangle rule in {chain} for ipset {ipset_name} with mark {fwmark}")
        else:
            errors.append(f"{chain}: {output}")
            logger.error(f"Failed to add mangle rule in {chain}: {output}")
    
    if errors:
        return False, "; ".join(errors)
    return True, "Mangle rules added"


def remove_mangle_rule(ipset_name: str, fwmark: int, rule_id: int) -> tuple[bool, str]:
    """
    Remove iptables mangle rules for a specific ipset.
    
    Args:
        ipset_name: Name of the ipset
        fwmark: Firewall mark value
        rule_id: Rule ID for tracking
    
    Returns:
        Tuple of (success, message)
    """
    errors = []
    
    for chain in ['OUTPUT', 'PREROUTING']:
        if not rule_exists(chain, ipset_name, fwmark, rule_id):
            continue
        
        success, output = run_command([
            'iptables', '-t', 'mangle', '-D', chain,
            '-m', 'set', '--match-set', ipset_name, 'dst',
            '-j', 'MARK', '--set-mark', str(fwmark),
            '-m', 'comment', '--comment', get_comment(rule_id)
        ])
        
        if success:
            logger.info(f"Removed mangle rule from {chain} for ipset {ipset_name}")
        else:
            errors.append(f"{chain}: {output}")
    
    if errors:
        return False, "; ".join(errors)
    return True, "Mangle rules removed"


def list_plugin_rules() -> list[dict]:
    """
    List all iptables rules created by this plugin.
    
    Returns:
        List of rule dictionaries with chain, ipset, fwmark info
    """
    rules = []
    
    for chain in ['OUTPUT', 'PREROUTING']:
        success, output = run_command([
            'iptables', '-t', 'mangle', '-L', chain, '-n', '-v', '--line-numbers'
        ])
        
        if not success:
            continue
        
        for line in output.split('\n'):
            if COMMENT_PREFIX in line:
                rules.append({
                    'chain': chain,
                    'raw': line
                })
    
    return rules


def cleanup_all_rules() -> int:
    """
    Remove all iptables rules created by this plugin.
    
    Returns:
        Number of rules removed
    """
    removed = 0
    
    for chain in ['OUTPUT', 'PREROUTING']:
        # Get all rules with line numbers
        success, output = run_command([
            'iptables', '-t', 'mangle', '-L', chain, '-n', '--line-numbers'
        ])
        
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
                'iptables', '-t', 'mangle', '-D', chain, str(line_num)
            ])
            if success:
                removed += 1
    
    logger.info(f"Cleaned up {removed} iptables rules")
    return removed
