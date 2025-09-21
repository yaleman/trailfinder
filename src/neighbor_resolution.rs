//! Global neighbor discovery and resolution system

use super::*;
use crate::config::DeviceState;
use tracing::{debug, info, warn};

/// Resolve all neighbor relationships across all devices
/// This processes CDP/LLDP data and establishes bidirectional peer relationships
pub fn resolve_all_neighbor_relationships(
    device_states: &mut [DeviceState],
) -> Result<usize, TrailFinderError> {
    let mut relationships_established = 0;

    // First pass: collect all neighbor data and convert to structured format
    let mut all_neighbor_info: Vec<(usize, Vec<NeighborInfo>)> = Vec::new();

    for (device_index, device_state) in device_states.iter().enumerate() {
        let neighbors = extract_neighbor_info_from_device(device_state)?;
        if !neighbors.is_empty() {
            debug!(
                "Device {} has {} neighbors",
                device_state.device.hostname,
                neighbors.len()
            );
            all_neighbor_info.push((device_index, neighbors));
        }
    }

    // Second pass: resolve neighbors and establish bidirectional relationships
    for (device_index, neighbors) in all_neighbor_info {
        let device_hostname = device_states[device_index].device.hostname.clone();

        for neighbor_info in neighbors {
            // Find the peer device by hostname (with fuzzy matching)
            if let Some(peer_device_index) =
                find_device_by_hostname_fuzzy(&neighbor_info.remote_hostname, device_states)
            {
                if peer_device_index == device_index {
                    continue; // Skip self-references
                }

                // Validate local interface exists
                if !device_states[device_index]
                    .device
                    .has_interface_id(neighbor_info.local_interface_id)
                {
                    warn!(
                        "Invalid local interface ID {} in neighbor data for device {}",
                        neighbor_info.local_interface_id, device_hostname
                    );
                    continue;
                }

                // Find peer interface by name
                let peer_interface_id = if neighbor_info.remote_interface == "unknown" {
                    // For MikroTik neighbor data, we don't know the remote interface
                    // Try bilateral discovery: find the peer device's neighbor data that references us
                    debug!("Attempting bilateral discovery for unknown remote interface");

                    let current_device_hostname = &device_states[device_index].device.hostname;
                    let peer_device = &device_states[peer_device_index].device;

                    // Look through the peer device's interfaces to find one that has neighbor data referencing us
                    let mut found_interface_id = None;
                    for interface in &peer_device.interfaces {
                        for neighbor_data in interface.neighbour_string_data.values() {
                            // Check if this neighbor data references our hostname
                            if let Some(peer_hostname) = extract_hostname_from_cdp(neighbor_data)
                                && peer_hostname == *current_device_hostname
                            {
                                debug!(
                                    "Found bilateral relationship: peer interface '{}' reports neighbor '{}'",
                                    interface.name, peer_hostname
                                );
                                found_interface_id = Some(interface.interface_id);
                                break;
                            }
                        }
                        if found_interface_id.is_some() {
                            break;
                        }
                    }

                    if found_interface_id.is_none() {
                        debug!("No bilateral relationship found for unknown remote interface");
                    }

                    found_interface_id
                } else {
                    device_states[peer_device_index]
                        .device
                        .find_interface_id_by_name(&neighbor_info.remote_interface)
                };
                let peer_device_hostname = device_states[peer_device_index].device.hostname.clone();

                if let Some(peer_interface_id) = peer_interface_id {
                    // Get interface name for logging before borrowing mutably
                    let local_interface_name = device_states[device_index]
                        .device
                        .get_interface(neighbor_info.local_interface_id)
                        .map(|i| i.name.clone())
                        .unwrap_or_else(|| {
                            debug!(
                                "Couldn't match interface for local interface ID {}",
                                neighbor_info.local_interface_id
                            );
                            "unknown".to_string()
                        });

                    // Establish bidirectional peer relationship using split_at_mut to avoid borrow conflicts
                    if device_index < peer_device_index {
                        let (left, right) = device_states.split_at_mut(peer_device_index);
                        establish_bidirectional_peer_relationship(
                            &mut left[device_index],
                            neighbor_info.local_interface_id,
                            &mut right[0],
                            peer_interface_id,
                            &neighbor_info.connection_type,
                        )?;
                    } else {
                        let (left, right) = device_states.split_at_mut(device_index);
                        establish_bidirectional_peer_relationship(
                            &mut right[0],
                            neighbor_info.local_interface_id,
                            &mut left[peer_device_index],
                            peer_interface_id,
                            &neighbor_info.connection_type,
                        )?;
                    }

                    relationships_established += 1;
                    info!(
                        "Established peer relationship: {}:{} <-> {}:{}",
                        device_hostname,
                        local_interface_name,
                        peer_device_hostname,
                        neighbor_info.remote_interface
                    );
                } else {
                    warn!(
                        "Could not find interface '{}' on peer device '{}'",
                        neighbor_info.remote_interface, neighbor_info.remote_hostname
                    );
                }
            } else {
                debug!(
                    "Could not find peer device for hostname '{}'",
                    neighbor_info.remote_hostname
                );
            }
        }
    }

    info!(
        "Established {} neighbor relationships",
        relationships_established
    );
    Ok(relationships_established)
}

/// Extract structured neighbor information from raw CDP/LLDP data
fn extract_neighbor_info_from_device(
    device_state: &DeviceState,
) -> Result<Vec<NeighborInfo>, TrailFinderError> {
    let mut neighbor_infos = Vec::new();

    for interface in &device_state.device.interfaces {
        for raw_neighbor_data in interface.neighbour_string_data.values() {
            // Parse the raw neighbor data based on the discovery protocol
            let parsed_neighbor_infos = parse_raw_neighbor_data(
                raw_neighbor_data,
                interface.interface_id,
                interface.mac_address,
            )?;

            neighbor_infos.extend(parsed_neighbor_infos);
        }
    }

    Ok(neighbor_infos)
}

/// Parse raw neighbor data (CDP/LLDP) into structured NeighborInfo
fn parse_raw_neighbor_data(
    raw_data: &str,
    local_interface_id: Uuid,
    local_mac: Option<MacAddress>,
) -> Result<Vec<NeighborInfo>, TrailFinderError> {
    // Detect protocol type
    let protocol = detect_neighbor_protocol(raw_data);

    match protocol {
        NeighborProtocol::Cdp => parse_cdp_neighbor_data(raw_data, local_interface_id, local_mac),
        NeighborProtocol::Lldp => parse_lldp_neighbor_data(raw_data, local_interface_id, local_mac),
        NeighborProtocol::Unknown => {
            debug!("Unknown neighbor protocol format: {}", raw_data);
            Ok(vec![])
        }
    }
}

#[derive(Debug, PartialEq)]
enum NeighborProtocol {
    Cdp,
    Lldp,
    Unknown,
}

fn detect_neighbor_protocol(raw_data: &str) -> NeighborProtocol {
    if raw_data.contains("Local Intf:") && raw_data.contains("Chassis id:") {
        NeighborProtocol::Lldp
    } else if raw_data.contains("Device ID:") || raw_data.contains("Port ID (outgoing port):") {
        NeighborProtocol::Cdp
    } else {
        NeighborProtocol::Unknown
    }
}

/// Parse CDP neighbor data into NeighborInfo structures
fn parse_cdp_neighbor_data(
    raw_data: &str,
    local_interface_id: Uuid,
    local_mac: Option<MacAddress>,
) -> Result<Vec<NeighborInfo>, TrailFinderError> {
    // Look for hostname in the raw data
    let remote_hostname = extract_hostname_from_cdp(raw_data)
        .unwrap_or_else(|| "unknown remote hostname".to_string());

    // Look for remote interface
    let remote_interfaces = extract_remote_interface_from_cdp(raw_data);
    if remote_interfaces.is_empty() {
        return Err(TrailFinderError::Parse(format!(
            "Could not find remote interface in CDP data ({raw_data})"
        )));
    }

    debug!(
        "Found remote interfaces: {:?} in cdp data '{raw_data}'",
        remote_interfaces
    );

    // Create a NeighborInfo entry for each remote interface
    let mut neighbor_infos = Vec::new();
    for remote_interface in remote_interfaces {
        // Determine connection type from interface names
        let connection_type = NeighborInfo::determine_connection_type(&remote_interface, None);

        neighbor_infos.push(NeighborInfo {
            remote_hostname: remote_hostname.clone(),
            remote_interface,
            remote_mac_address: None, // Would be parsed from CDP data
            local_interface_id,
            local_mac_address: local_mac,
            connection_type,
            discovery_protocol: "CDP".to_string(),
            management_ip: None, // CDP doesn't typically provide management IP
            system_description: None, // CDP doesn't provide detailed system description
            capabilities: Vec::new(), // CDP capabilities handled differently
        });
    }

    Ok(neighbor_infos)
}

/// Parse LLDP neighbor data into NeighborInfo structures
fn parse_lldp_neighbor_data(
    raw_data: &str,
    local_interface_id: Uuid,
    local_mac: Option<MacAddress>,
) -> Result<Vec<NeighborInfo>, TrailFinderError> {
    let remote_hostname = extract_hostname_from_lldp(raw_data)
        .unwrap_or_else(|| "unknown remote hostname".to_string());

    let remote_interfaces = extract_remote_interface_from_lldp(raw_data);
    if remote_interfaces.is_empty() {
        return Err(TrailFinderError::Parse(format!(
            "Could not find remote interface in LLDP data: {}", raw_data
        )));
    }

    let management_ip = extract_management_ip_from_lldp(raw_data);
    let system_description = extract_system_description_from_lldp(raw_data);
    let capabilities = extract_capabilities_from_lldp(raw_data);

    let mut neighbor_infos = Vec::new();
    for remote_interface in remote_interfaces {
        let connection_type = determine_connection_type_from_lldp(&remote_interface, &capabilities);

        neighbor_infos.push(NeighborInfo {
            remote_hostname: remote_hostname.clone(),
            remote_interface,
            remote_mac_address: None, // Could extract from chassis ID if MAC format
            local_interface_id,
            local_mac_address: local_mac,
            connection_type,
            discovery_protocol: "LLDP".to_string(),
            management_ip: management_ip.clone(),
            system_description: system_description.clone(),
            capabilities: capabilities.clone(),
        });
    }

    Ok(neighbor_infos)
}

/// Extract hostname from CDP data
fn extract_hostname_from_cdp(cdp_data: &str) -> Option<String> {
    // Look for common CDP hostname patterns
    let lines: Vec<&str> = cdp_data.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let line = line.trim();

        if line.starts_with("Device ID:") {
            return Some(line.strip_prefix("Device ID:")?.trim().to_string());
        }

        // Handle MikroTik neighbor format: both terse and tabular formats
        if !line.is_empty() && !line.starts_with('#') && !line.starts_with("Columns:") {
            let parts: Vec<&str> = line.split_whitespace().collect();

            // Try new terse format first - look for identity= key
            if let Some(identity) = find_kv(&parts, "identity") {
                return Some(identity);
            }

            // Old tabular format: "0  sfp-sfpplus1  10.0.99.2  A0:23:9F:7B:2E:33  C3650.example.com"
            if parts.len() >= 5 && parts[0].chars().all(|c| c.is_numeric()) {
                return Some(parts[4].to_string());
            }

            // Handle Cisco CDP multi-line format:
            // Line 1: "rb5009.example.com"
            // Line 2: "Ten 1/1/3         98                R    MikroTik  vlan40"
            if parts.len() == 1 && !parts[0].is_empty() && i + 1 < lines.len() {
                let next_line = lines[i + 1].trim();
                let next_parts = next_line.split_whitespace().collect::<Vec<&str>>();

                // Check if next line looks like CDP interface info with 6+ parts (Ten 1/1/3 101 R MikroTik bridge/sfp-sfpplus1)
                // and the first part doesn't look like a hostname (no dots)
                if next_parts.len() >= 6 && !next_parts[0].contains('.') {
                    return Some(parts[0].to_string());
                }
            }

            // Handle Cisco CDP single-line format: "MagickNet         Ten 1/1/3         102               R    MikroTik  vlan40"
            if parts.len() >= 6
                && !parts[0].starts_with("Device")
                && !parts[0].starts_with("Capability")
            {
                return Some(parts[0].to_string());
            }
        }
    }
    None
}

/// Extract remote interface from CDP data
fn extract_remote_interface_from_cdp(cdp_data: &str) -> Vec<String> {
    // fall back to trying to k-v search it
    if let Some(val) = find_kv(
        &cdp_data.split_whitespace().collect::<Vec<&str>>(),
        "interface",
    ) {
        return val.split(",").map(|s| s.trim().to_string()).collect();
    }

    // Look for interface information in CDP data
    for line in cdp_data.lines() {
        let line = line.trim();
        if let Some(port_id) = line.split("Port ID (outgoing port):").nth(1) {
            return vec![port_id.to_string()];
        }

        // Handle MikroTik neighbor format - the interface is already parsed and stored elsewhere
        // For MikroTik data, we don't have the remote interface in the neighbor data
        // Return a generic value for now
        if !line.is_empty() && !line.starts_with('#') && !line.starts_with("Columns:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 && parts[0].chars().all(|c| c.is_numeric()) {
                // MikroTik format doesn't provide remote interface info in neighbor data
                return Vec::new();
            }

            // Handle Cisco CDP format: "MagickNet         Ten 1/1/3         102               R    MikroTik  vlan40"
            // The last field might be the remote interface
            if parts.len() >= 6
                && !parts[0].starts_with("Device")
                && !parts[0].starts_with("Capability")
                && let Some(last) = parts.last()
            {
                return vec![last.to_string()];
            }
        }
    }
    Vec::new()
}

/// Extract system name from LLDP data
fn extract_hostname_from_lldp(lldp_data: &str) -> Option<String> {
    for line in lldp_data.lines() {
        if let Some(name) = line.strip_prefix("System Name:") {
            let name = name.trim();
            if !name.is_empty() && name != "not advertised" {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Extract port ID from LLDP data
fn extract_remote_interface_from_lldp(lldp_data: &str) -> Vec<String> {
    for line in lldp_data.lines() {
        if let Some(port_id) = line.strip_prefix("Port id:") {
            let port_id = port_id.trim();
            if !port_id.is_empty() && port_id != "not advertised" {
                return vec![port_id.to_string()];
            }
        }
    }
    Vec::new()
}

/// Extract management IP addresses from LLDP data
fn extract_management_ip_from_lldp(lldp_data: &str) -> Option<String> {
    let lines: Vec<&str> = lldp_data.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("Management Addresses:") {
            // Check next few lines for IP addresses
            for next_line in lines.iter().skip(i + 1).take(4) {
                let next_line = next_line.trim();
                if let Some(ip) = next_line.strip_prefix("IP:") {
                    return Some(ip.trim().to_string());
                }
            }
        }
    }
    None
}

/// Extract system description from LLDP data
fn extract_system_description_from_lldp(lldp_data: &str) -> Option<String> {
    let mut in_description = false;
    let mut description_lines = Vec::new();

    for line in lldp_data.lines() {
        if line.starts_with("System Description:") {
            if let Some(desc) = line.strip_prefix("System Description:") {
                let desc = desc.trim();
                if !desc.is_empty() && desc != "not advertised" {
                    description_lines.push(desc.to_string());
                    in_description = true;
                }
            }
        } else if in_description {
            // Check if this line is part of the description or a new field
            if line.contains(":") && !line.starts_with(' ') {
                break; // New field started
            } else {
                description_lines.push(line.trim().to_string());
            }
        }
    }

    if !description_lines.is_empty() {
        Some(description_lines.join(" "))
    } else {
        None
    }
}

/// Extract capabilities from LLDP data
fn extract_capabilities_from_lldp(lldp_data: &str) -> Vec<String> {
    for line in lldp_data.lines() {
        if let Some(caps) = line.strip_prefix("Enabled Capabilities:") {
            let caps = caps.trim();
            if !caps.is_empty() && caps != "not advertised" {
                return caps.split(',')
                    .map(|c| c.trim().to_string())
                    .filter(|c| !c.is_empty())
                    .collect();
            }
        }
    }
    Vec::new()
}

/// Determine connection type based on LLDP interface name and capabilities
fn determine_connection_type_from_lldp(interface_name: &str, capabilities: &[String]) -> PeerConnection {
    // Enhanced logic based on LLDP capabilities
    if capabilities.contains(&"B".to_string()) {
        PeerConnection::Trunk // Bridge capability suggests trunk
    } else if interface_name.to_lowercase().contains("vlan") {
        // Try to extract VLAN number from interface name
        if let Some(vlan_id) = NeighborInfo::parse_vlan_from_interface_name(interface_name) {
            PeerConnection::Vlan(vlan_id)
        } else {
            PeerConnection::Trunk // Fallback if VLAN ID can't be parsed
        }
    } else {
        PeerConnection::Trunk // Default fallback
    }
}

/// Find device by hostname with fuzzy matching, including system identity
pub fn find_device_by_hostname_fuzzy(
    hostname: &str,
    device_states: &[DeviceState],
) -> Option<usize> {
    // First try exact match against hostname (case-insensitive)
    for (index, device_state) in device_states.iter().enumerate() {
        if device_state.device.hostname.eq_ignore_ascii_case(hostname) {
            return Some(index);
        }
    }

    // Try exact match against system identity (case-insensitive)
    for (index, device_state) in device_states.iter().enumerate() {
        if let Some(ref system_identity) = device_state.device.system_identity
            && system_identity.eq_ignore_ascii_case(hostname)
        {
            return Some(index);
        }
    }

    // Try without domain against hostname (case-insensitive)
    let hostname_short = hostname.split('.').next().unwrap_or(hostname);
    for (index, device_state) in device_states.iter().enumerate() {
        let device_hostname_short = device_state
            .device
            .hostname
            .split('.')
            .next()
            .unwrap_or(&device_state.device.hostname);
        if device_hostname_short.eq_ignore_ascii_case(hostname_short) {
            return Some(index);
        }
    }

    // Try without domain against system identity (case-insensitive)
    for (index, device_state) in device_states.iter().enumerate() {
        if let Some(ref system_identity) = device_state.device.system_identity {
            let identity_short = system_identity.split('.').next().unwrap_or(system_identity);
            if identity_short.eq_ignore_ascii_case(hostname_short) {
                return Some(index);
            }
        }
    }

    None
}

/// Establish bidirectional peer relationship between two interfaces
fn establish_bidirectional_peer_relationship(
    device_a: &mut DeviceState,
    interface_a_id: Uuid,
    device_b: &mut DeviceState,
    interface_b_id: Uuid,
    connection_type: &PeerConnection,
) -> Result<(), TrailFinderError> {
    // Add device B's interface as peer to device A's interface
    if let Some(interface_a) = device_a.device.get_interface_mut(interface_a_id) {
        interface_a
            .peers
            .entry(connection_type.clone())
            .or_default()
            .push(interface_b_id);
    }

    // Add device A's interface as peer to device B's interface
    if let Some(interface_b) = device_b.device.get_interface_mut(interface_b_id) {
        interface_b
            .peers
            .entry(connection_type.clone())
            .or_default()
            .push(interface_a_id);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_detection() {
        let lldp_data = r#"
Local Intf: Gi1/0/1
Chassis id: a0:23:9f:2b:b3:3f
Port id: Gi2/0/1
System Name: CORE-SW-01
"#;

        let cdp_data = r#"
Device ID: neighbor1
Platform: cisco
Port ID (outgoing port): GigabitEthernet0/2
"#;

        let unknown_data = "random text without protocol markers";

        assert_eq!(detect_neighbor_protocol(lldp_data), NeighborProtocol::Lldp);
        assert_eq!(detect_neighbor_protocol(cdp_data), NeighborProtocol::Cdp);
        assert_eq!(detect_neighbor_protocol(unknown_data), NeighborProtocol::Unknown);
    }

    #[test]
    fn test_lldp_hostname_extraction() {
        let lldp_data = r#"
Local Intf: Gi1/0/1
System Name: CORE-SW-01
Port id: Gi2/0/1
"#;

        assert_eq!(extract_hostname_from_lldp(lldp_data), Some("CORE-SW-01".to_string()));

        let no_name_data = r#"
Local Intf: Gi1/0/1
System Name: not advertised
Port id: Gi2/0/1
"#;

        assert_eq!(extract_hostname_from_lldp(no_name_data), None);

        let empty_name_data = r#"
Local Intf: Gi1/0/1
System Name:
Port id: Gi2/0/1
"#;

        assert_eq!(extract_hostname_from_lldp(empty_name_data), None);
    }

    #[test]
    fn test_lldp_interface_extraction() {
        let lldp_data = r#"
Local Intf: Gi1/0/1
Port id: Gi2/0/1
System Name: CORE-SW-01
"#;

        assert_eq!(extract_remote_interface_from_lldp(lldp_data), vec!["Gi2/0/1"]);

        let no_port_data = r#"
Local Intf: Gi1/0/1
Port id: not advertised
System Name: CORE-SW-01
"#;

        assert_eq!(extract_remote_interface_from_lldp(no_port_data), Vec::<String>::new());
    }

    #[test]
    fn test_lldp_management_ip_extraction() {
        let lldp_data = r#"
Local Intf: Gi1/0/1
System Name: CORE-SW-01
Management Addresses:
  IP: 10.0.99.2
Port id: Gi2/0/1
"#;

        assert_eq!(extract_management_ip_from_lldp(lldp_data), Some("10.0.99.2".to_string()));

        let no_mgmt_data = r#"
Local Intf: Gi1/0/1
System Name: CORE-SW-01
Port id: Gi2/0/1
"#;

        assert_eq!(extract_management_ip_from_lldp(no_mgmt_data), None);
    }

    #[test]
    fn test_lldp_capabilities_extraction() {
        let lldp_data = r#"
Local Intf: Gi1/0/1
System Name: CORE-SW-01
Enabled Capabilities: B,R
Port id: Gi2/0/1
"#;

        assert_eq!(extract_capabilities_from_lldp(lldp_data), vec!["B", "R"]);

        let spaced_caps = r#"
Local Intf: Gi1/0/1
System Name: CORE-SW-01
Enabled Capabilities: B, R, T
Port id: Gi2/0/1
"#;

        assert_eq!(extract_capabilities_from_lldp(spaced_caps), vec!["B", "R", "T"]);

        let no_caps_data = r#"
Local Intf: Gi1/0/1
System Name: CORE-SW-01
Enabled Capabilities: not advertised
Port id: Gi2/0/1
"#;

        assert_eq!(extract_capabilities_from_lldp(no_caps_data), Vec::<String>::new());
    }

    #[test]
    fn test_lldp_connection_type_determination() {
        // Test bridge capability
        let bridge_caps = vec!["B".to_string()];
        assert_eq!(
            determine_connection_type_from_lldp("Gi1/0/1", &bridge_caps),
            PeerConnection::Trunk
        );

        // Test VLAN interface
        let no_caps = vec![];
        assert_eq!(
            determine_connection_type_from_lldp("vlan40", &no_caps),
            PeerConnection::Vlan(40)
        );

        // Test default case
        assert_eq!(
            determine_connection_type_from_lldp("eth0", &no_caps),
            PeerConnection::Trunk
        );
    }

    #[test]
    fn test_lldp_system_description_extraction() {
        let lldp_data = r#"
Local Intf: Gi1/0/1
System Description: Cisco IOS Software, IOS-XE Software
System Name: CORE-SW-01
Port id: Gi2/0/1
"#;

        assert_eq!(
            extract_system_description_from_lldp(lldp_data),
            Some("Cisco IOS Software, IOS-XE Software".to_string())
        );

        let multiline_desc = r#"
Local Intf: Gi1/0/1
System Description: Cisco IOS Software
IOS-XE Software, Catalyst L3 Switch
Port id: Gi2/0/1
"#;

        let result = extract_system_description_from_lldp(multiline_desc);
        assert!(result.is_some());
        let desc = result.unwrap();
        assert!(desc.contains("Cisco IOS Software"));
        assert!(desc.contains("IOS-XE Software"));
    }
}
