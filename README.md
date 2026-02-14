# Domain Routing Plugin for WGDashboard

A powerful plugin for [WGDashboard](https://github.com/WGDashboard/WGDashboard) that enables selective domain-based routing through WireGuard VPN tunnels. Route specific domains through your default gateway (bypass VPN) or targeted WireGuard peers while keeping other traffic on the VPN.

## Features

- **Domain-Based Routing**: Route traffic for specific domains through different network paths
- **Static Route Support**: Configure direct IP/CIDR-based routing rules
- **WireGuard Integration**: Seamlessly works with existing WGDashboard WireGuard configurations
- **Automatic DNS Resolution**: Uses DNSMasq for automatic IP resolution and ipset population
- **Web Interface**: Built-in web UI for easy rule management
- **REST API**: Full API for programmatic control
- **Dual-Stack Support**: IPv4 and IPv6 support for modern networks
- **Real-Time Monitoring**: Background routing engine monitors and applies rules automatically

## Use Cases

- **Split Tunneling**: Route streaming services through default gateway while keeping other traffic on VPN
- **Latency Optimization**: Send local traffic directly while routing remote traffic through VPN
- **Selective VPN Routing**: Choose which domains use VPN and which bypass it
- **Multi-Peer Routing**: Direct different domains to different WireGuard peers

## Requirements

- Python 3.8+
- WGDashboard
- Linux system with:
  - `iptables` / `ip6tables`
  - `ipset`
  - `ip` (iproute2)
  - `dnsmasq`

### WireGuard Configuration Requirements

For this plugin to work properly, your WireGuard setup must be configured as follows:

1. **Client DNS**: Set client DNS to the WireGuard server's local IP address (so DNS queries go through the tunnel and are handled by dnsmasq)

2. **Server Configuration** (`Table = off`): In your WireGuard server configuration, set `Table = off` to prevent WireGuard from automatically managing the routing table. The plugin will handle policy routing instead.
   ```ini
   [Interface]
   PrivateKey = ...
   Address = 10.0.0.1/24
   ListenPort = 51820
   Table = off
   ```

3. **Peer AllowedIPs**: For peers through which you want to route traffic, set `AllowedIPs = 0.0.0.0/0, ::/0` to allow all traffic through the tunnel.
   ```ini
   [Peer]
   PublicKey = ...
   AllowedIPs = 0.0.0.0/0, ::/0
   ```

## Installation

### Docker Compose (Recommended)

The plugin is designed to work with WGDashboard in a Docker Compose setup with dnsmasq.

1. **Clone this repository** to your project directory:
```bash
git clone <repository-url>
cd domain-routing-repo
```

The repository includes the plugin in the `plugins/domain_routing/` directory:
```
.
├── docker-compose.yaml
├── Dockerfile
└── plugins/
    └── domain_routing/
        ├── main.py
        ├── config.ini
        ├── requirements.txt
        ├── modules/
        └── web/
```

2. **Configure the plugin** by editing `plugins/domain_routing/config.ini`:

> **Recommendation:** Set a secure `auth_token` before starting the container. If not set, a token will be auto-generated and displayed in the logs.

```ini
[WebServer]
port = 8081
host = 0.0.0.0
auth_enabled = true
auth_token = your-secure-random-token-here

[Database]
path = /opt/wgdashboard/src/plugins/domain_routing/db/routing_rules.db

[Routing]
monitoring_interval = 30
dnsmasq_config_path = /etc/dnsmasq.d/wgdashboard-domains.conf
```

To generate a secure token, you can use:
```bash
openssl rand -base64 32
```

3. **Review the `docker-compose.yaml`** configuration:
```yaml
services:
  wgdashboard:
    build: .
    restart: unless-stopped
    container_name: wgdashboard
    ports:
      - 127.0.0.1:8081:8081/tcp
      - 127.0.0.1:10086:10086/tcp
      - 51820:51820/udp
      - 51821:51821/udp
    volumes:
      - aconf:/etc/amnezia/amneziawg
      - conf:/etc/wireguard
      - data:/data
      - ./plugins:/opt/wgdashboard/src/plugins
      - dnsmasq:/etc/dnsmasq.d/
    cap_add:
      - NET_ADMIN
    networks:
      - wgdash
    sysctls:
      - net.ipv4.conf.all.src_valid_mark=1
      - net.ipv6.conf.all.forwarding=1
      - net.ipv6.conf.default.forwarding=1

  dnsmasq:
    image: dockurr/dnsmasq
    container_name: dnsmasq
    environment:
      DNS1: "127.0.0.11"
      DNS2: "127.0.0.11"
    network_mode: service:wgdashboard
    pid: service:wgdashboard
    cap_add:
      - NET_ADMIN
    restart: always
    volumes:
      - dnsmasq:/etc/dnsmasq.d/

volumes:
  aconf:
  conf:
  data:
  dnsmasq:

networks:
  wgdash:
    enable_ipv6: true
```

The `Dockerfile` extends the official WGDashboard image with `ipset` support:
```dockerfile
ARG VERSION=latest
FROM ghcr.io/wgdashboard/wgdashboard:${VERSION}

RUN apk update && \
    apk add --no-cache ipset
```

4. **Build and start the services**:
```bash
docker-compose up --build -d
```

Or to start without rebuilding:
```bash
docker-compose up -d
```

5. **Access the plugin**:
   - WGDashboard: http://localhost:8081
   - Check logs for the generated auth token:
   ```bash
   docker-compose logs wgdashboard | grep "AUTH TOKEN"
   ```

### Manual Installation

For non-Docker setups:

1. Copy the `plugins/domain_routing/` directory to your WGDashboard plugins folder:
```bash
cp -r plugins/domain_routing/ /path/to/wgdashboard/plugins/
```

2. Install Python dependencies:
```bash
pip install -r plugins/domain_routing/requirements.txt
```

3. Configure the plugin by editing `config.ini` (see Configuration section below).

4. Ensure dnsmasq is installed and configured to include the plugin's configuration directory.

5. Restart WGDashboard to load the plugin.

## Configuration

### Web Server Settings

| Option | Default | Description |
|--------|---------|-------------|
| `port` | 8081 | Port for the plugin's web interface |
| `host` | 0.0.0.0 | Bind address for the web server |
| `auth_enabled` | true | Enable/disable token authentication |
| `auth_token` | auto-generated | Authentication token (generated on first run) |

### Routing Settings

| Option | Default | Description |
|--------|---------|-------------|
| `monitoring_interval` | 30 | Seconds between routing rule sync checks |
| `dnsmasq_config_path` | /etc/dnsmasq.d/wgdashboard-domains.conf | Path to dnsmasq config file |

## Usage

### Web Interface

Access the web interface at `http://host:port` (default: `http://localhost:8081`).

On first run, an authentication token is generated and displayed in the logs:
```
GENERATED NEW AUTH TOKEN: <your-token>
```

Access the UI with: `http://localhost:8081?token=<your-token>`

### Creating Domain Routing Rules

1. Navigate to the Domain Rules section
2. Click "Add Rule"
3. Configure:
   - **Name**: Descriptive name for the rule
   - **Domain**: Domain to route (e.g., `example.com`)
   - **Target Type**: `default_gateway` or `wireguard_peer`
   - **Target Config**: WireGuard configuration name (for peer targets)
   - **Target Peer**: Specific peer public key (optional)
   - **Priority**: Rule priority (lower = higher priority)

### Creating Static Routes

1. Navigate to the Static Routes section
2. Click "Add Static Route"
3. Configure:
   - **Name**: Descriptive name
   - **Destination**: IP/CIDR (e.g., `192.168.1.0/24`)
   - **Target Type**: `default_gateway`, `wireguard_peer`, or `interface`
   - **Gateway**: Gateway IP (optional)
   - **Interface**: Outgoing interface (optional)

## REST API

### Authentication

Include the token in requests:
```bash
curl -H "Authorization: Bearer <token>" http://localhost:8081/api/status
```

### Endpoints

#### Status & Health
- `GET /api/status` - Get plugin status and statistics

#### WireGuard Configurations
- `GET /api/wg/configurations` - List available WireGuard configurations
- `GET /api/wg/peers/<config_name>` - List peers for a configuration

#### Domain Routing Rules
- `GET /api/rules` - List all routing rules
- `GET /api/rules/<id>` - Get a specific rule
- `POST /api/rules` - Create a new rule
- `PUT /api/rules/<id>` - Update a rule
- `DELETE /api/rules/<id>` - Delete a rule
- `POST /api/rules/<id>/toggle` - Toggle rule enabled state
- `POST /api/rules/<id>/apply` - Force apply a rule
- `POST /api/rules/apply-all` - Reapply all enabled rules
- `POST /api/rules/cleanup` - Remove all applied rules

#### Static Routes
- `GET /api/static-routes` - List all static routes
- `GET /api/static-routes/<id>` - Get a specific route
- `POST /api/static-routes` - Create a new route
- `PUT /api/static-routes/<id>` - Update a route
- `DELETE /api/static-routes/<id>` - Delete a route
- `POST /api/static-routes/<id>/toggle` - Toggle route enabled state
- `POST /api/static-routes/<id>/apply` - Force apply a route
- `POST /api/static-routes/apply-all` - Reapply all enabled routes

### Example API Usage

```bash
# Get status
curl -H "Authorization: Bearer <token>" http://localhost:8081/api/status

# Create a domain rule
curl -X POST -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Bypass Netflix",
    "domain": "netflix.com",
    "target_type": "default_gateway",
    "enabled": true,
    "priority": 100
  }' \
  http://localhost:8081/api/rules

# Create a WireGuard peer rule
curl -X POST -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Route via US Peer",
    "domain": "example.com",
    "target_type": "wireguard_peer",
    "target_config": "wg0",
    "target_peer": "<peer_public_key>"
  }' \
  http://localhost:8081/api/rules
```

## Architecture

The plugin consists of several integrated components:

### Core Modules

- **Routing Engine** ([`modules/routing_engine.py`](plugins/domain_routing/modules/routing_engine.py)): Monitors database and applies routing rules
- **Database** ([`modules/database.py`](plugins/domain_routing/modules/database.py)): SQLite database for rules and state management
- **WireGuard Interface** ([`modules/wg_interface.py`](plugins/domain_routing/modules/wg_interface.py)): Interface to WGDashboard WireGuard configurations

### System Integration

- **IPSet Manager** ([`modules/ipset_manager.py`](plugins/domain_routing/modules/ipset_manager.py)): Manages ipsets for IP grouping
- **IPTables Manager** ([`modules/iptables_manager.py`](plugins/domain_routing/modules/iptables_manager.py)): Handles packet marking rules
- **Policy Routing** ([`modules/policy_routing.py`](plugins/domain_routing/modules/policy_routing.py)): Configures routing tables and rules
- **DNSMasq Integration** ([`modules/dnsmasq_integration.py`](plugins/domain_routing/modules/dnsmasq_integration.py)): Auto-generates dnsmasq config

### Web Layer

- **API** ([`web/api.py`](plugins/domain_routing/web/api.py)): REST API endpoints
- **App** ([`web/app.py`](plugins/domain_routing/web/app.py)): Flask application setup
- **Auth** ([`web/auth.py`](plugins/domain_routing/web/auth.py)): Token-based authentication

## How It Works

1. **Rule Definition**: Define domain or IP-based routing rules via web UI or API
2. **DNS Resolution**: DNSMasq resolves domains and populates ipsets automatically
3. **Packet Marking**: iptables rules mark packets destined for ipset members
4. **Policy Routing**: ip rules direct marked packets to specific routing tables
5. **Route Selection**: Custom routing tables send traffic through the chosen gateway/interface

## Database Schema

The plugin uses SQLite with the following tables:

- `routing_rules` - Domain routing rules
- `static_routes` - Static IP/CIDR routes
- `applied_state` - Applied state tracking for domain rules
- `static_route_applied_state` - Applied state tracking for static routes
- `plugin_settings` - Plugin configuration storage

## Troubleshooting

### Check Plugin Status
```bash
curl -H "Authorization: Bearer <token>" http://localhost:8081/api/status
```

### View Logs
The plugin logs to stdout/stderr. Check WGDashboard logs for plugin output.

### Reset All Rules
```bash
curl -X POST -H "Authorization: Bearer <token>" http://localhost:8081/api/rules/cleanup
```

### Common Issues

- **Rules not applying**: Check that dnsmasq is running and includes the plugin config
- **Authentication failed**: Verify the auth token in config.ini or logs
- **Routing not working**: Ensure iptables/ipset/iproute2 are installed and functional

## Project Structure

```
.
├── docker-compose.yaml    # Docker Compose configuration
├── Dockerfile             # Custom WGDashboard image with ipset
└── plugins/
    └── domain_routing/    # Plugin directory
        ├── main.py              # Plugin entry point
        ├── config.ini           # Configuration file
        ├── requirements.txt     # Python dependencies
        ├── db/                  # Database directory
        ├── modules/             # Core functionality
        │   ├── database.py      # Database operations
        │   ├── routing_engine.py # Routing rule engine
        │   ├── wg_interface.py  # WireGuard integration
        │   ├── ipset_manager.py # IPSet management
        │   ├── iptables_manager.py # IPTables rules
        │   ├── policy_routing.py # Routing table management
        │   └── dnsmasq_integration.py # DNSMasq config
        └── web/                 # Web interface
            ├── app.py           # Flask application
            ├── api.py           # REST API endpoints
            ├── auth.py          # Authentication
            └── static/          # Static assets (HTML, CSS, JS)
```

## License

This plugin is part of the WGDashboard ecosystem.

## Contributing

Contributions are welcome! Please ensure your code follows the existing patterns and includes appropriate tests.
