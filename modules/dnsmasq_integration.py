"""
dnsmasq integration for Domain Routing Plugin.
Generates dnsmasq configuration for automatic ipset population.
"""

import os
import subprocess
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Default dnsmasq config path
DEFAULT_CONFIG_PATH = "/etc/dnsmasq.d/wgdashboard-domains.conf"

# Header comment for generated config
CONFIG_HEADER = """# WGDashboard Domain Routing Plugin
# Auto-generated - DO NOT EDIT MANUALLY
# Changes will be overwritten when rules are updated

"""


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


def is_dnsmasq_installed() -> bool:
    """
    Check if dnsmasq is available.
    First try 'which dnsmasq', if that fails check if process is running.
    """
    # First try to find dnsmasq binary
    success, _ = run_command(['which', 'dnsmasq'], check=False)
    if success:
        return True
    
    # If not found, check if it's running (e.g., in container)
    return is_dnsmasq_running()


def is_dnsmasq_running() -> bool:
    """
    Check if dnsmasq is running.
    Since dnsmasq runs in a separate container with shared PID namespace,
    we check for the process directly.
    """
    # Check if dnsmasq process exists in shared PID namespace
    success, _ = run_command(['pidof', 'dnsmasq'], check=False)
    if success:
        return True
    
    # Fallback: try pgrep
    success, _ = run_command(['pgrep', '-x', 'dnsmasq'], check=False)
    return success


def validate_config(config_path: str) -> tuple[bool, str]:
    """
    Validate dnsmasq configuration syntax.
    
    Args:
        config_path: Path to configuration file
    
    Returns:
        Tuple of (valid, message)
    """
    success, output = run_command(['dnsmasq', '--test'], check=False)
    
    if success or 'syntax check OK' in output:
        return True, "Configuration valid"
    
    return False, output


def generate_config(rules: list[dict], config_path: str = DEFAULT_CONFIG_PATH) -> tuple[bool, str]:
    """
    Generate dnsmasq configuration file with ipset directives.
    Supports dual-stack by adding entries to both IPv4 and IPv6 ipsets.
    
    Args:
        rules: List of routing rules with 'domain', 'ipset_name', and 'ipset_name_v6' keys
        config_path: Path where to write the configuration
    
    Returns:
        Tuple of (success, message)
    """
    # Build config content
    lines = [CONFIG_HEADER]
    
    for rule in rules:
        if not rule.get('enabled', True):
            continue
        
        domain = rule.get('domain', '')
        ipset_name = rule.get('ipset_name', '')
        ipset_name_v6 = rule.get('ipset_name_v6', '')
        rule_name = rule.get('name', 'Unknown')
        
        if not domain or not ipset_name:
            continue
        
        # Add comment for rule
        lines.append(f"# Rule: {rule_name}")
        
        # Handle multiple domains (comma-separated or list)
        domains = domain if isinstance(domain, list) else [domain]
        for d in domains:
            d = d.strip()
            if d:
                # dnsmasq ipset directive with both v4 and v6 ipsets
                # Format: ipset=/domain/ipset_v4,ipset_v6
                if ipset_name_v6:
                    lines.append(f"ipset=/{d}/{ipset_name},{ipset_name_v6}")
                else:
                    lines.append(f"ipset=/{d}/{ipset_name}")
        
        lines.append("")
    
    config_content = "\n".join(lines)
    
    # Ensure directory exists
    config_dir = os.path.dirname(config_path)
    if config_dir and not os.path.exists(config_dir):
        try:
            os.makedirs(config_dir, exist_ok=True)
        except PermissionError:
            return False, f"Cannot create directory: {config_dir}"
    
    # Write config file
    try:
        with open(config_path, 'w') as f:
            f.write(config_content)
        logger.info(f"Generated dnsmasq config at {config_path}")
    except PermissionError:
        return False, f"Permission denied writing to {config_path}"
    except Exception as e:
        return False, str(e)
    
    # Validate config
    if is_dnsmasq_installed():
        valid, msg = validate_config(config_path)
        if not valid:
            logger.warning(f"dnsmasq config validation warning: {msg}")
    
    return True, f"Config written to {config_path}"


def reload_dnsmasq() -> tuple[bool, str]:
    """
    Reload dnsmasq to apply configuration changes using SIGHUP.
    
    Returns:
        Tuple of (success, message)
    """
    if not is_dnsmasq_installed():
        logger.warning("dnsmasq is not installed")
        return False, "dnsmasq not installed"
    
    # Get dnsmasq PID and send SIGHUP
    success, pid = run_command(['pidof', 'dnsmasq'], check=False)
    if success and pid:
        success, output = run_command(['kill', '-HUP', pid.strip()], check=False)
        if success:
            logger.info(f"Reloaded dnsmasq via SIGHUP (PID: {pid.strip()})")
            return True, "dnsmasq reloaded"
        return False, f"Failed to send SIGHUP: {output}"
    
    # Fallback: try pkill -HUP if pidof didn't work
    success, output = run_command(['pkill', '-HUP', 'dnsmasq'], check=False)
    if success:
        logger.info("Reloaded dnsmasq via SIGHUP (pkill)")
        return True, "dnsmasq reloaded"
    
    return False, "Failed to reload dnsmasq: process not found"


def remove_config(config_path: str = DEFAULT_CONFIG_PATH) -> tuple[bool, str]:
    """
    Remove the dnsmasq configuration file.
    
    Args:
        config_path: Path to configuration file
    
    Returns:
        Tuple of (success, message)
    """
    if not os.path.exists(config_path):
        return True, "Config file does not exist"
    
    try:
        os.remove(config_path)
        logger.info(f"Removed dnsmasq config: {config_path}")
        return True, "Config file removed"
    except PermissionError:
        return False, f"Permission denied removing {config_path}"
    except Exception as e:
        return False, str(e)


def update_and_reload(rules: list[dict], config_path: str = DEFAULT_CONFIG_PATH) -> tuple[bool, str]:
    """
    Update dnsmasq configuration and reload the service.
    
    Args:
        rules: List of routing rules
        config_path: Path to configuration file
    
    Returns:
        Tuple of (success, message)
    """
    # Generate new config
    success, msg = generate_config(rules, config_path)
    if not success:
        return False, f"Failed to generate config: {msg}"
    
    # Reload dnsmasq if running
    if is_dnsmasq_running():
        success, msg = reload_dnsmasq()
        if not success:
            logger.warning(f"Failed to reload dnsmasq: {msg}")
            # Don't fail - config is written, just couldn't reload
    
    return True, "dnsmasq configuration updated"


def cleanup(config_path: str = DEFAULT_CONFIG_PATH) -> tuple[bool, str]:
    """
    Clean up dnsmasq configuration and reload.
    
    Args:
        config_path: Path to configuration file
    
    Returns:
        Tuple of (success, message)
    """
    success, msg = remove_config(config_path)
    
    if is_dnsmasq_running():
        reload_dnsmasq()
    
    return success, msg
