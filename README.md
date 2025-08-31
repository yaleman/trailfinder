# Trailfinder

A Rust application for network device discovery and configuration parsing. Trailfinder can SSH into network devices, automatically identify their brand and type, parse their configurations, and maintain a JSON-based inventory.

## Features

- **Automatic Device Discovery** - SSH into devices and identify brand/type automatically
- **Configuration Parsing** - Parse network device configurations (currently supports MikroTik)
- **SSH Config Integration** - Uses your existing `~/.ssh/config` for authentication
- **Multiple Auth Methods** - Supports ssh-agent, key files, and password authentication
- **JSON Inventory** - Maintains device inventory with caching to avoid unnecessary connections
- **Extensible Architecture** - Plugin-based parser system for adding new device brands

## Supported Devices

- **MikroTik** - RouterOS devices (routers, switches, access points)
- **Cisco** - Basic identification support
- **Ubiquiti** - Basic identification support

## Installation

### Prerequisites

- Rust 1.70+ (uses 2024 edition)
- SSH client configuration (optional but recommended)

### Build from Source

```bash
git clone <repository-url>
cd trailfinder
cargo build --release
```

## Usage

### 1. Create Device Configuration

Create a `devices.json` file with your network devices:

```json
{
  "devices": {
    "router01": {
      "hostname": "router01",
      "ip_address": "192.168.1.1",
      "brand": null,
      "device_type": null,
      "owner": "Named(\"IT Department\")",
      "ssh_username": null,
      "ssh_port": 22,
      "ssh_key_path": null,
      "last_interrogated": null,
      "notes": "Main gateway router - will use SSH config"
    }
  },
  "ssh_timeout_seconds": 30
}
```

### 2. Run Discovery

```bash
# Uses SSH config and ssh-agent by default
cargo run

# Or use password authentication
SSH_PASSWORD=mypassword cargo run
```

### 3. View Results

The application will:

- Connect to each device via SSH
- Identify the device brand and type
- Update the `devices.json` file with discovered information
- Cache results to avoid re-identification for 24 hours (configurable)

## SSH Authentication

Trailfinder supports multiple authentication methods in priority order:

### 1. SSH Config Integration (Recommended)

Add devices to your `~/.ssh/config`:

```text
Host router01
    HostName 192.168.1.1
    User admin
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
```

### 2. Manual Configuration

Configure authentication in `devices.json`:

```json
{
  "ssh_username": "admin",
  "ssh_key_path": "~/.ssh/id_ed25519"
}
```

### 3. Password Authentication

Set the `SSH_PASSWORD` environment variable for password-based auth (least secure).

## Configuration

### Device Configuration Fields

- `hostname` - Device hostname for SSH config lookup
- `ip_address` - IP address to connect to
- `brand` - Device brand (auto-detected, can be `null`)
- `device_type` - Device type (auto-detected, can be `null`)
- `owner` - Device owner information
- `ssh_username` - SSH username (optional if in SSH config)
- `ssh_port` - SSH port (default: 22)
- `ssh_key_path` - Path to SSH private key (supports `~/`)
- `last_interrogated` - Timestamp of last identification
- `notes` - Optional notes about the device

### Application Settings

- `ssh_timeout_seconds` - SSH connection timeout
- `use_ssh_agent` - Whether to use ssh-agent globally (optional, defaults to true if omitted)

## Architecture

### Core Components

- **ConfParser Trait** - Extensible interface for device configuration parsers
- **Device Models** - Data structures for devices, interfaces, and routes
- **SSH Client** - Multi-method SSH authentication and command execution
- **Config Management** - JSON-based device inventory with caching

### Adding New Device Support

To add support for a new device brand:

1. Create a new parser in `src/brand/newbrand.rs`
2. Implement the `ConfParser` trait
3. Add identification logic to `DeviceIdentifier`
4. Add the new brand to `DeviceBrand` enum

Example:

```rust
pub struct CiscoParser {
    // ... fields
}

impl ConfParser for CiscoParser {
    fn parse_interfaces(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        // Parse Cisco interface configuration
    }
    
    fn parse_routes(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        // Parse Cisco routing table
    }
}
```

## Development

### Running Tests

```bash
cargo test
```

### Code Formatting

```bash
cargo fmt
```

### Linting

```bash
cargo clippy
```

## Security Considerations

- **SSH Keys Preferred** - Use SSH key authentication over passwords
- **ssh-agent Integration** - Leverages ssh-agent for secure key management
- **No Credential Storage** - Passwords are only accepted via environment variables
- **SSH Config Respect** - Honors your existing SSH security settings

## License

MPL2.0? I think.

## Contributing

Please create issues for features or bugs! If you're looking to make a PR for a change, please create/note you're doing it in an issue so we can discuss implementation beforehand!

## Troubleshooting

### Connection Issues

- Verify SSH connectivity: `ssh username@hostname`
- Check SSH config syntax: `ssh -F ~/.ssh/config -T hostname`
- Ensure ssh-agent is running: `ssh-add -l`

### Authentication Failures

- Try manual SSH connection first
- Check SSH key permissions: `chmod 600 ~/.ssh/id_*`
- Verify username in SSH config or device configuration
- Enable verbose SSH logging for debugging

### Device Identification Issues

- Check if device responds to identification commands
- Review device-specific command output
- Add debug logging to see raw command responses

## Thanks

- [d3](https://d3js.org) for visualisation (and cdnjs for [the mirror I grab things from](https://cdnjs.com/libraries/d3))
