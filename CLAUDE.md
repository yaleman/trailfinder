# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Trailfinder is a Rust application for network device discovery and configuration parsing. The application can SSH into network devices, automatically identify their brand/type, parse their configurations, and maintain a JSON-based inventory. Currently implements MikroTik parser but is designed to support multiple device brands.

## Commands

### Building
- `cargo build` - Build the project
- `cargo run` - Run the main application

### Testing
- `cargo test` - Run all tests
- `cargo test test_parse_mikrotik` - Run specific test

### Development
- `cargo check` - Fast compile check without producing binaries
- `cargo clippy` - Lint checker
- `cargo fmt` - Format code

## Architecture

The codebase follows a standard Rust library + binary structure:

- **src/lib.rs** - Core data models and trait definitions:
  - `Device` struct - Main data structure for network devices with interface references
  - `Interface` struct - Network interface with unique ID generation (`interface_id()` method)  
  - `Route` struct - Network routes that reference interfaces by ID
  - `ConfParser` trait - Extensible interface for device configuration parsers
  - Enums for `DeviceType`, `InterfaceType`, `RouteType`, and `Owner`

- **src/main.rs** - Main application logic for device discovery and identification

- **src/config.rs** - JSON-based configuration management:
  - `AppConfig` - Application configuration with device inventory
  - `DeviceConfig` - Per-device configuration including SSH details
  - `DeviceBrand` - Enum for supported device manufacturers

- **src/ssh.rs** - SSH client functionality:
  - `SshClient` - SSH connection with multiple authentication methods
  - `DeviceIdentifier` - Automatic device brand/type detection
  - SSH config integration - reads `~/.ssh/config` for connection details

- **src/brand/mikrotik.rs** - MikroTik-specific parser implementing `ConfParser`

- **Test data files** - Sample MikroTik configuration data for testing

## Device Configuration

The application uses a `devices.json` file to store device inventory. Each device entry includes:
- Hostname and IP address  
- SSH connection details (username, port, key path)
- Authentication preferences (ssh-agent, identity files)
- Brand and device type (auto-detected)
- Last interrogation timestamp for caching

## SSH Authentication

The application supports multiple SSH authentication methods in priority order:

1. **SSH Config Integration** - Automatically reads `~/.ssh/config` for:
   - Username from `User` directive
   - Identity files from `IdentityFile` directive  
   - ssh-agent usage based on `IdentitiesOnly` setting
   
2. **Manual Configuration** - Fallback to device-specific settings:
   - ssh-agent authentication (default: enabled)
   - SSH key file authentication
   - Password authentication (via `SSH_PASSWORD` environment variable)

The application tries SSH config first, then falls back to manual config if SSH config fails.

## Key Dependencies

- `serde` - Serialization/deserialization with derive macros
- `serde_json` - JSON configuration file support
- `ssh2` - SSH client functionality for device connection
- `ssh_config` - SSH config file parsing for authentication
- `dirs` - Cross-platform home directory detection
- `chrono` - Timestamp handling for identification caching  
- `uuid` - Unique device ID generation
- `tokio` - Async runtime (for future async features)

## Testing Data

The project includes sample MikroTik configuration files that are used in tests. The parser functions expect MikroTik's specific command output format for interfaces and routes.
- no task is complete unless you can run 'just check' and there's no errors or warnings