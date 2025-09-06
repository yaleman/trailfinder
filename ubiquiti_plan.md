# Ubiquiti Brand Implementation Plan

## Overview

Implement Ubiquiti device support for trailfinder network discovery tool. Ubiquiti devices (UniFi switches, access points) are Linux-based embedded systems that can be interrogated using standard Linux commands via SSH.

## Architecture Changes Required

### 1. Create Ubiquiti Brand Module

**File**: `src/brand/ubiquiti.rs`

Implement the `DeviceHandler` trait with the following methods:

- `parse_interfaces()` - Parse network interfaces from `ip addr show`
- `parse_routes()` - Parse routing table from `ip route show`
- `parse_neighbors()` - Parse ARP/neighbor table from `ip neigh show`
- `parse_vlans()` - Parse VLAN configuration (if applicable)
- `parse_ipsec()` - Not applicable for Ubiquiti devices
- `get_commands()` - Return Linux commands for device interrogation

### 2. Linux Commands for Device Interrogation

Use reliable Linux commands instead of potentially missing utilities:

```rust
const GET_HOSTNAME_COMMAND: &str = "cat /proc/sys/kernel/hostname";
const GET_INTERFACES_COMMAND: &str = "ip addr show";
const GET_ROUTES_COMMAND: &str = "ip route show";
const GET_NEIGHBORS_COMMAND: &str = "ip neigh show";
const GET_SYSTEM_INFO_COMMAND: &str = "uname -a";
const GET_MODEL_INFO_COMMAND: &str = "cat /proc/cpuinfo | grep -E '^(model name|Hardware)'";
```

### 3. Device Type Detection

Implement logic to distinguish between UniFi device types:

- **Switch**: Check for bridge interfaces, VLAN capabilities
- **Access Point**: Check for wireless interfaces, hostapd processes

### 4. Device Identification Enhancement

**File**: `src/ssh.rs`

Add Ubiquiti detection logic to `DeviceIdentifier::identify_device()`:

```rust
// Check for Ubiquiti UniFi devices
if let Ok(model_output) = ssh_client.execute_command("cat /proc/cpuinfo | grep -i ubiquiti") {
    if !model_output.trim().is_empty() {
        return Ok((DeviceBrand::Ubiquiti, DeviceType::Switch)); // Default, refine based on further detection
    }
}

// Alternative detection via system info
if let Ok(uname_output) = ssh_client.execute_command("uname -a") {
    if uname_output.contains("UBNT") || uname_output.contains("ubnt") {
        // Determine device type based on additional checks
        let device_type = determine_ubiquiti_device_type(&ssh_client)?;
        return Ok((DeviceBrand::Ubiquiti, device_type));
    }
}
```

### 5. Module Integration

**File**: `src/brand/mod.rs`

Add Ubiquiti module:

```rust
pub mod ubiquiti;
```

Update `interrogate_device_by_brand()` to handle Ubiquiti devices:

```rust
DeviceBrand::Ubiquiti => {
    ubiquiti::UbiquitiHandler::new().interrogate_device(ssh_client, device_config)
}
```

## Implementation Details

### Interface Parsing

Parse `ip addr show` output to extract:

- Interface names (eth0, br0, wlan0, etc.)
- IP addresses and netmasks
- MAC addresses
- Interface status (UP/DOWN)
- MTU settings

### Route Parsing

Parse `ip route show` output to extract:

- Default gateway
- Network routes
- Interface-specific routes
- Route metrics

### Neighbor Discovery

Parse `ip neigh show` output for:

- ARP table entries
- Neighbor MAC addresses
- Reachability status

### Device Type Classification

Implement `determine_ubiquiti_device_type()` function:

1. Check for wireless interfaces (`iw dev` or `/proc/net/wireless`)
2. Check for bridge interfaces (`brctl show` or `ip link show type bridge`)
3. Check running processes for UniFi-specific daemons
4. Fallback to Switch type if detection is unclear

## Testing Strategy

### Test Data Collection

Create sample command outputs in `src/tests/`:

- `ubiquiti_switch_ip_addr.txt`
- `ubiquiti_switch_ip_route.txt`
- `ubiquiti_switch_ip_neigh.txt`
- `ubiquiti_ap_ip_addr.txt`
- `ubiquiti_ap_ip_route.txt`
- `ubiquiti_ap_uname.txt`

### Unit Tests

Implement comprehensive tests in `src/brand/ubiquiti.rs`:

- Test interface parsing for switch configurations
- Test interface parsing for access point configurations
- Test route parsing for various network setups
- Test neighbor parsing for ARP entries
- Test device type detection logic
- Test error handling for malformed command outputs

Target: 20+ tests following existing brand test patterns

## Error Handling

Handle common Linux command variations:

- Missing `ip` command (fallback to `ifconfig`, `route`)
- Permission issues with `/proc` filesystem
- Network namespace considerations
- Command timeout handling

## Configuration Support

Extend device configuration to support:

- SSH key authentication (standard Linux SSH)
- Custom SSH ports for UniFi devices
- Network namespace SSH access if needed

## Integration Points

### SSH Client Enhancement

Ensure SSH client can handle:

- Linux-style command execution
- Standard shell environment
- Error code interpretation

### Device Model Support

Add Ubiquiti-specific device models:

- UniFi Switch series
- UniFi Access Point series
- UniFi Gateway series (future)

## Implementation Order

1. Create basic `src/brand/ubiquiti.rs` module structure
2. Implement command constants and basic parsing
3. Add device identification logic to `ssh.rs`
4. Integrate with brand module system
5. Create test data from real device outputs
6. Implement comprehensive unit tests
7. Test against actual UniFi devices
8. Refine parsing based on real-world output variations

## Success Criteria

- Ubiquiti devices are automatically detected and classified
- Interface, route, and neighbor information is correctly parsed
- Device type (Switch vs AccessPoint) is accurately determined
- All tests pass with 20+ test cases
- Real UniFi switch and AP devices are successfully interrogated
- Integration with existing trailfinder workflow is seamless

## Future Enhancements

- UniFi Controller API integration for centralized device management
- Wireless client information parsing for access points
- VLAN configuration parsing for advanced switch setups
- UniFi-specific metrics and monitoring data collection
