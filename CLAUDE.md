# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Trailfinder is a Rust application for network device discovery and configuration parsing. The application can SSH into network devices, automatically identify their brand/type, parse their configurations, and maintain a JSON-based inventory. Currently implements MikroTik and Cisco parsers with comprehensive test coverage.

## Commands

### Building

- `cargo build --quiet` - Build the project
- `cargo run --quiet` - Run the main application
- `cargo run web --quiet` - Run the web server

### Testing

- `cargo test --quiet` - Run all tests (173+ tests with comprehensive coverage)
- `cargo test --quiet test_parse_mikrotik` - Run specific test
- `cargo test --quiet mikrotik` - Run all MikroTik parser tests
- `cargo test --quiet cisco` - Run all Cisco parser tests
- `cargo test --quiet lib_tests` - Run core library tests
- `cargo test --quiet main_tests` - Run CLI integration tests
- `cargo test --quiet ssh_tests` - Run SSH client tests

### Development

- `cargo check --quiet` - Fast compile check without producing binaries
- `cargo clippy --all-targets --quiet` - Lint checker
- `cargo fmt` - Format code

### Logging

The application uses structured logging via the `tracing` crate.

Examples:

- `cargo run` - Run with default INFO level logging
- `cargo run -- --debug` - Run with detailed debugging
- `cargo run --release` - Run release build with minimal output

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
- **src/brand/cisco.rs** - Cisco-specific parser implementing `ConfParser`

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

The project includes sample MikroTik and Cisco system responses in `src/tests/` that are used in comprehensive unit tests:
- `src/tests/mikrotik_*.txt` - MikroTik RouterOS command outputs
- `src/tests/cisco_*.txt` - Cisco IOS command outputs

## Test Coverage

The project maintains comprehensive test coverage across all major components:
- **CLI Integration Tests** - 25+ tests covering command parsing, config validation, error handling
- **SSH Client Tests** - 20+ tests covering connection management, authentication, device identification  
- **Core Library Tests** - 32+ tests covering data models, serialization, error handling
- **Brand Parser Tests** - 43+ tests covering MikroTik (23) and Cisco (20) configuration parsing
- **Total: 173+ tests** providing robust validation of network discovery functionality

Test coverage includes:
- Edge case handling and error conditions
- Configuration parsing for multiple device types
- Network topology discovery and neighbor detection
- Interface and routing table parsing
- Device identification and classification

## Current Development Tasks

See TODO.md for the current development plan and task status.

## Development Guidelines

- no task is complete unless you can run `just check` and there's no errors or warnings
- when editing Cargo.toml always try to use cargo commands unless it's impossible
- clean up TODO.md when commiting checked-off tasks
- update TODO.md with tasks before and after they're done
- always use a todo list in TODO.md when working on complex tasks to track progress and remain on track
- if wanting to test the app, just use `cargo run` rather than `cargo build` then running the binary
- when using javascript you MUST use DOM manipulation to update UI objects, NEVER use .innerHTML or similar
- never try to use port 3000 to try and run the server, use a high port for testing

## Testing Philosophy

- Prefer comprehensive unit tests with edge case coverage over integration tests
- Test error conditions and malformed input handling
- Use real device output samples from `src/tests/` directory
- Maintain test coverage above 70% for all core modules
- Each brand parser should have 20+ tests covering all parsing functions