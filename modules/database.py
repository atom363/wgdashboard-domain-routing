"""
Database module for Domain Routing Plugin
Handles SQLite database schema and CRUD operations for routing rules.
"""

import os
import sqlite3
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, asdict


@dataclass
class RoutingRule:
    """Represents a domain routing rule."""
    id: Optional[int] = None
    name: str = ""
    domain: str = ""
    target_type: str = "default_gateway"  # "default_gateway" or "wireguard_peer"
    target_config: Optional[str] = None   # WG config name (e.g., "wg0")
    target_peer: Optional[str] = None     # Peer public key
    fwmark: int = 100
    routing_table: int = 100
    enabled: bool = True
    priority: int = 100
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class AppliedState:
    """Tracks the applied state of a routing rule."""
    id: Optional[int] = None
    rule_id: int = 0
    ipset_name: str = ""
    applied_ips: str = "[]"  # JSON array
    status: str = "pending"  # "active", "failed", "pending"
    last_applied: Optional[str] = None


@dataclass
class StaticRoute:
    """Represents a static IP route (not domain-based)."""
    id: Optional[int] = None
    name: str = ""
    destination: str = ""  # IP/CIDR (e.g., "192.168.1.0/24" or "2001:db8::/64")
    gateway: Optional[str] = None  # Gateway IP (optional, uses interface if not set)
    interface: Optional[str] = None  # Outgoing interface (e.g., "wg0", "eth0")
    target_type: str = "default_gateway"  # "default_gateway", "wireguard_peer", or "interface"
    target_config: Optional[str] = None   # WG config name for wireguard_peer
    target_peer: Optional[str] = None     # Peer public key for wireguard_peer
    enabled: bool = True
    priority: int = 100
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


class Database:
    """Database manager for routing rules."""

    def __init__(self, db_path: str):
        """Initialize database connection."""
        self.db_path = db_path
        self._ensure_directory()
        self._init_schema()

    def _ensure_directory(self):
        """Ensure the database directory exists."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        """Initialize database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Create routing_rules table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS routing_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                domain TEXT NOT NULL,
                target_type TEXT NOT NULL DEFAULT 'default_gateway',
                target_config TEXT,
                target_peer TEXT,
                fwmark INTEGER NOT NULL DEFAULT 100,
                routing_table INTEGER NOT NULL DEFAULT 100,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)

        # Create applied_state table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS applied_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL,
                ipset_name TEXT NOT NULL,
                applied_ips TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'pending',
                last_applied TEXT,
                FOREIGN KEY (rule_id) REFERENCES routing_rules(id) ON DELETE CASCADE
            )
        """)

        # Create plugin_settings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS plugin_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Create static_routes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS static_routes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                destination TEXT NOT NULL,
                gateway TEXT,
                interface TEXT,
                target_type TEXT NOT NULL DEFAULT 'default_gateway',
                target_config TEXT,
                target_peer TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)

        # Create static_route_applied_state table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS static_route_applied_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                route_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                last_applied TEXT,
                FOREIGN KEY (route_id) REFERENCES static_routes(id) ON DELETE CASCADE
            )
        """)

        conn.commit()
        conn.close()

    # CRUD Operations for Routing Rules

    def get_all_rules(self) -> list[RoutingRule]:
        """Get all routing rules."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM routing_rules ORDER BY priority ASC, id ASC")
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_rule(row) for row in rows]

    def get_enabled_rules(self) -> list[RoutingRule]:
        """Get all enabled routing rules."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM routing_rules WHERE enabled = 1 ORDER BY priority ASC, id ASC"
        )
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_rule(row) for row in rows]

    def get_rule_by_id(self, rule_id: int) -> Optional[RoutingRule]:
        """Get a routing rule by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM routing_rules WHERE id = ?", (rule_id,))
        row = cursor.fetchone()
        conn.close()
        return self._row_to_rule(row) if row else None

    def create_rule(self, rule: RoutingRule) -> RoutingRule:
        """Create a new routing rule."""
        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()

        cursor.execute("""
            INSERT INTO routing_rules 
            (name, domain, target_type, target_config, target_peer, fwmark, 
             routing_table, enabled, priority, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rule.name, rule.domain, rule.target_type, rule.target_config,
            rule.target_peer, rule.fwmark, rule.routing_table,
            1 if rule.enabled else 0, rule.priority, now, now
        ))

        rule.id = cursor.lastrowid
        rule.created_at = now
        rule.updated_at = now
        conn.commit()
        conn.close()
        return rule

    def update_rule(self, rule: RoutingRule) -> bool:
        """Update an existing routing rule."""
        if rule.id is None:
            return False

        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()

        cursor.execute("""
            UPDATE routing_rules SET
                name = ?, domain = ?, target_type = ?, target_config = ?,
                target_peer = ?, fwmark = ?, routing_table = ?, enabled = ?,
                priority = ?, updated_at = ?
            WHERE id = ?
        """, (
            rule.name, rule.domain, rule.target_type, rule.target_config,
            rule.target_peer, rule.fwmark, rule.routing_table,
            1 if rule.enabled else 0, rule.priority, now, rule.id
        ))

        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success

    def delete_rule(self, rule_id: int) -> bool:
        """Delete a routing rule."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Delete applied state first
        cursor.execute("DELETE FROM applied_state WHERE rule_id = ?", (rule_id,))
        cursor.execute("DELETE FROM routing_rules WHERE id = ?", (rule_id,))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success

    def toggle_rule(self, rule_id: int) -> Optional[bool]:
        """Toggle a rule's enabled state. Returns new enabled state."""
        rule = self.get_rule_by_id(rule_id)
        if not rule:
            return None

        conn = self._get_connection()
        cursor = conn.cursor()
        new_enabled = 0 if rule.enabled else 1
        now = datetime.now().isoformat()

        cursor.execute(
            "UPDATE routing_rules SET enabled = ?, updated_at = ? WHERE id = ?",
            (new_enabled, now, rule_id)
        )
        conn.commit()
        conn.close()
        return bool(new_enabled)

    # CRUD Operations for Static Routes

    def get_all_static_routes(self) -> list[StaticRoute]:
        """Get all static routes."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM static_routes ORDER BY priority ASC, id ASC")
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_static_route(row) for row in rows]

    def get_enabled_static_routes(self) -> list[StaticRoute]:
        """Get all enabled static routes."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM static_routes WHERE enabled = 1 ORDER BY priority ASC, id ASC"
        )
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_static_route(row) for row in rows]

    def get_static_route_by_id(self, route_id: int) -> Optional[StaticRoute]:
        """Get a static route by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM static_routes WHERE id = ?", (route_id,))
        row = cursor.fetchone()
        conn.close()
        return self._row_to_static_route(row) if row else None

    def create_static_route(self, route: StaticRoute) -> StaticRoute:
        """Create a new static route."""
        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()

        cursor.execute("""
            INSERT INTO static_routes 
            (name, destination, gateway, interface, target_type, target_config, target_peer, enabled, priority, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            route.name, route.destination, route.gateway, route.interface,
            route.target_type, route.target_config, route.target_peer,
            1 if route.enabled else 0, route.priority, now, now
        ))

        route.id = cursor.lastrowid
        route.created_at = now
        route.updated_at = now
        conn.commit()
        conn.close()
        return route

    def update_static_route(self, route: StaticRoute) -> bool:
        """Update an existing static route."""
        if route.id is None:
            return False

        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()

        cursor.execute("""
            UPDATE static_routes SET
                name = ?, destination = ?, gateway = ?, interface = ?,
                target_type = ?, target_config = ?, target_peer = ?, enabled = ?,
                priority = ?, updated_at = ?
            WHERE id = ?
        """, (
            route.name, route.destination, route.gateway, route.interface,
            route.target_type, route.target_config, route.target_peer,
            1 if route.enabled else 0, route.priority, now, route.id
        ))

        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success

    def delete_static_route(self, route_id: int) -> bool:
        """Delete a static route."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Delete applied state first
        cursor.execute("DELETE FROM static_route_applied_state WHERE route_id = ?", (route_id,))
        cursor.execute("DELETE FROM static_routes WHERE id = ?", (route_id,))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success

    def toggle_static_route(self, route_id: int) -> Optional[bool]:
        """Toggle a static route's enabled state. Returns new enabled state."""
        route = self.get_static_route_by_id(route_id)
        if not route:
            return None

        conn = self._get_connection()
        cursor = conn.cursor()
        new_enabled = 0 if route.enabled else 1
        now = datetime.now().isoformat()

        cursor.execute(
            "UPDATE static_routes SET enabled = ?, updated_at = ? WHERE id = ?",
            (new_enabled, now, route_id)
        )
        conn.commit()
        conn.close()
        return bool(new_enabled)

    # Static Route Applied State Operations

    def get_static_route_applied_state(self, route_id: int) -> Optional[dict]:
        """Get the applied state for a static route."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM static_route_applied_state WHERE route_id = ?", (route_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {
                'id': row['id'],
                'route_id': row['route_id'],
                'status': row['status'],
                'last_applied': row['last_applied']
            }
        return None

    def set_static_route_applied_state(self, route_id: int, status: str) -> dict:
        """Create or update applied state for a static route."""
        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()

        # Check if state exists
        cursor.execute("SELECT id FROM static_route_applied_state WHERE route_id = ?", (route_id,))
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE static_route_applied_state SET
                    status = ?, last_applied = ?
                WHERE route_id = ?
            """, (status, now, route_id))
            route_state_id = existing['id']
        else:
            cursor.execute("""
                INSERT INTO static_route_applied_state (route_id, status, last_applied)
                VALUES (?, ?, ?)
            """, (route_id, status, now))
            route_state_id = cursor.lastrowid

        conn.commit()
        conn.close()
        return {
            'id': route_state_id,
            'route_id': route_id,
            'status': status,
            'last_applied': now
        }

    def delete_static_route_applied_state(self, route_id: int) -> bool:
        """Delete applied state for a static route."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM static_route_applied_state WHERE route_id = ?", (route_id,))
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success

    def clear_all_static_route_applied_states(self):
        """Clear all static route applied states."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM static_route_applied_state")
        conn.commit()
        conn.close()

    # Applied State Operations

    def get_applied_state(self, rule_id: int) -> Optional[AppliedState]:
        """Get the applied state for a rule."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM applied_state WHERE rule_id = ?", (rule_id,))
        row = cursor.fetchone()
        conn.close()
        return self._row_to_state(row) if row else None

    def get_all_applied_states(self) -> list[AppliedState]:
        """Get all applied states."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM applied_state")
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_state(row) for row in rows]

    def set_applied_state(self, state: AppliedState) -> AppliedState:
        """Create or update applied state for a rule."""
        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()

        # Check if state exists
        cursor.execute("SELECT id FROM applied_state WHERE rule_id = ?", (state.rule_id,))
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE applied_state SET
                    ipset_name = ?, applied_ips = ?, status = ?, last_applied = ?
                WHERE rule_id = ?
            """, (state.ipset_name, state.applied_ips, state.status, now, state.rule_id))
            state.id = existing['id']
        else:
            cursor.execute("""
                INSERT INTO applied_state (rule_id, ipset_name, applied_ips, status, last_applied)
                VALUES (?, ?, ?, ?, ?)
            """, (state.rule_id, state.ipset_name, state.applied_ips, state.status, now))
            state.id = cursor.lastrowid

        state.last_applied = now
        conn.commit()
        conn.close()
        return state

    def delete_applied_state(self, rule_id: int) -> bool:
        """Delete applied state for a rule."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM applied_state WHERE rule_id = ?", (rule_id,))
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success

    def clear_all_applied_states(self):
        """Clear all applied states."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM applied_state")
        conn.commit()
        conn.close()

    # Plugin Settings

    def get_setting(self, key: str) -> Optional[str]:
        """Get a plugin setting value."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM plugin_settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        conn.close()
        return row['value'] if row else None

    def set_setting(self, key: str, value: str):
        """Set a plugin setting value."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO plugin_settings (key, value) VALUES (?, ?)
        """, (key, value))
        conn.commit()
        conn.close()

    # Helper methods

    def _row_to_rule(self, row: sqlite3.Row) -> RoutingRule:
        """Convert a database row to a RoutingRule."""
        return RoutingRule(
            id=row['id'],
            name=row['name'],
            domain=row['domain'],
            target_type=row['target_type'],
            target_config=row['target_config'],
            target_peer=row['target_peer'],
            fwmark=row['fwmark'],
            routing_table=row['routing_table'],
            enabled=bool(row['enabled']),
            priority=row['priority'],
            created_at=row['created_at'],
            updated_at=row['updated_at']
        )

    def _row_to_state(self, row: sqlite3.Row) -> AppliedState:
        """Convert a database row to an AppliedState."""
        return AppliedState(
            id=row['id'],
            rule_id=row['rule_id'],
            ipset_name=row['ipset_name'],
            applied_ips=row['applied_ips'],
            status=row['status'],
            last_applied=row['last_applied']
        )

    def _row_to_static_route(self, row: sqlite3.Row) -> StaticRoute:
        """Convert a database row to a StaticRoute."""
        return StaticRoute(
            id=row['id'],
            name=row['name'],
            destination=row['destination'],
            gateway=row['gateway'],
            interface=row['interface'],
            target_type=row['target_type'],
            target_config=row['target_config'],
            target_peer=row['target_peer'],
            enabled=bool(row['enabled']),
            priority=row['priority'],
            created_at=row['created_at'],
            updated_at=row['updated_at']
        )

    def get_next_fwmark(self) -> int:
        """Get the next available fwmark value."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(fwmark) as max_mark FROM routing_rules")
        row = cursor.fetchone()
        conn.close()
        max_mark = row['max_mark'] if row and row['max_mark'] else 99
        return max_mark + 1

    def get_stats(self) -> dict:
        """Get database statistics."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as total FROM routing_rules")
        total_rules = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as enabled FROM routing_rules WHERE enabled = 1")
        enabled_rules = cursor.fetchone()['enabled']
        
        cursor.execute("SELECT COUNT(*) as active FROM applied_state WHERE status = 'active'")
        active_rules = cursor.fetchone()['active']
        
        cursor.execute("SELECT COUNT(*) as total FROM static_routes")
        total_static_routes = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as enabled FROM static_routes WHERE enabled = 1")
        enabled_static_routes = cursor.fetchone()['enabled']
        
        cursor.execute("SELECT COUNT(*) as active FROM static_route_applied_state WHERE status = 'active'")
        active_static_routes = cursor.fetchone()['active']
        
        conn.close()
        
        return {
            'total_rules': total_rules,
            'enabled_rules': enabled_rules,
            'active_rules': active_rules,
            'total_static_routes': total_static_routes,
            'enabled_static_routes': enabled_static_routes,
            'active_static_routes': active_static_routes
        }
