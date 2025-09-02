use crate::config::DeviceState;
use crate::web::*;
use crate::{
    Device, DeviceType, Interface, InterfaceAddress, InterfaceType, Owner, PeerConnection, Route,
    RouteType,
};
use mac_address::MacAddress;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

fn create_test_device_with_routes(
    hostname: &str,
    interface_id: uuid::Uuid,
    routes: Vec<Route>,
) -> DeviceState {
    let mut device = Device::new(
        hostname.to_string(),
        Some(format!("Test {}", hostname)),
        Owner::Named("test".to_string()),
        DeviceType::Router,
    );
    device.routes = routes;

    // Add a basic interface with the specified ID
    device.interfaces.push(Interface::new(
        interface_id,
        "eth0".to_string(),
        vec![],
        vec![InterfaceAddress::new(
            IpAddr::from_str("192.168.1.1").unwrap(),
            24,
        )],
        InterfaceType::Ethernet,
        None,
    ));

    DeviceState {
        device,
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        config_hash: 12345u64,
    }
}

fn create_test_route(target: &str, gateway: Option<&str>, interface_id: uuid::Uuid) -> Route {
    Route {
        target: cidr::IpCidr::from_str(target).unwrap(),
        gateway: gateway.map(|g| IpAddr::from_str(g).unwrap()),
        distance: Some(1),
        route_type: RouteType::Local(interface_id),
    }
}

fn build_test_topology(device_states: Vec<DeviceState>) -> NetworkTopology {
    let mut devices = Vec::new();
    let mut connections = Vec::new();
    let mut networks = HashMap::new();

    // Convert device states to network devices
    for device_state in &device_states {
        devices.push(NetworkDevice {
            device_id: device_state.device.device_id.to_string(),
            hostname: device_state.device.hostname.clone(),
            device_type: Some(device_state.device.device_type),
            position: None,
        });

        // Find interface addresses and build networks (simplified)
        for interface in &device_state.device.interfaces {
            for address in &interface.addresses {
                let network_key = match address.ip {
                    std::net::IpAddr::V4(ip) => {
                        let octets = ip.octets();
                        format!(
                            "{}.{}.{}.0/{}",
                            octets[0], octets[1], octets[2], address.prefix_length
                        )
                    }
                    std::net::IpAddr::V6(_) => format!("{}/{}", address.ip, address.prefix_length),
                };

                if !interface.vlans.is_empty() {
                    // If the interface has VLANs, treat each VLAN as a separate segment
                    for vlan_id in &interface.vlans {
                        let vlan_network_key = format!("{}-vlan{}", network_key, vlan_id);
                        let segment =
                            networks.entry(vlan_network_key.clone()).or_insert_with(|| {
                                NetworkSegment {
                                    network: vlan_network_key,
                                    vlan_id: Some(*vlan_id),
                                    devices: Vec::new(),
                                }
                            });

                        if !segment.devices.contains(&device_state.device.hostname) {
                            segment.devices.push(device_state.device.hostname.clone());
                        }
                    }
                } else {
                    // If the interface is bare, treat it as a single segment
                    let segment =
                        networks
                            .entry(network_key.clone())
                            .or_insert_with(|| NetworkSegment {
                                network: network_key,
                                vlan_id: None,
                                devices: Vec::new(),
                            });

                    if !segment.devices.contains(&device_state.device.hostname) {
                        segment.devices.push(device_state.device.hostname.clone());
                    }
                }
            }
        }

        // Find gateway connections through routes
        for route in &device_state.device.routes {
            if let Some(gateway_ip) = &route.gateway {
                let mut gateway_found = false;

                // Look for devices that have this gateway IP as an interface
                for other_device in &device_states {
                    if other_device.device.hostname == device_state.device.hostname {
                        continue;
                    }

                    for other_interface in &other_device.device.interfaces {
                        if other_interface
                            .addresses
                            .iter()
                            .any(|addr| &addr.ip == gateway_ip)
                        {
                            connections.push(NetworkConnection {
                                from: device_state.device.hostname.clone(),
                                to: other_device.device.hostname.clone(),
                                interface_from: format!("route-{}", route.target),
                                interface_to: Some(other_interface.name.clone()),
                                connection_type: ConnectionType::Gateway,
                            });
                            gateway_found = true;
                            break;
                        }
                    }
                    if gateway_found {
                        break;
                    }
                }

                // If gateway not found in our devices, it's an external gateway
                if !gateway_found {
                    connections.push(NetworkConnection {
                        from: device_state.device.hostname.clone(),
                        to: "internet".to_string(),
                        interface_from: format!("route-{}", route.target),
                        interface_to: Some(gateway_ip.to_string()),
                        connection_type: ConnectionType::Internet,
                    });
                }
            }
        }

        // Find CDP/neighbor connections through peer relationships
        for interface in &device_state.device.interfaces {
            for (peer_connection, peer_interface_ids) in &interface.peers {
                for peer_interface_id in peer_interface_ids {
                    // Find the peer interface in other devices
                    for other_device in &device_states {
                        if other_device.device.hostname == device_state.device.hostname {
                            continue;
                        }

                        if let Some(peer_interface) = other_device
                            .device
                            .interfaces
                            .iter()
                            .find(|iface| iface.interface_id == *peer_interface_id)
                        {
                            // Create CDP connection
                            let connection_info = match peer_connection {
                                PeerConnection::Untagged => "CDP",
                                PeerConnection::Vlan(vlan_id) => &format!("CDP-VLAN{}", vlan_id),
                                PeerConnection::Trunk => "CDP-Trunk",
                                PeerConnection::Management => "CDP-Management",
                                PeerConnection::Tunnel(name) => &format!("CDP-Tunnel({})", name),
                            };

                            connections.push(NetworkConnection {
                                from: device_state.device.device_id.to_string(),
                                to: other_device.device.device_id.to_string(),
                                interface_from: format!("{} ({})", interface.name, connection_info),
                                interface_to: Some(peer_interface.name.clone()),
                                connection_type: ConnectionType::CDP,
                            });
                        }
                    }
                }
            }
        }
    }

    // Add internet node if there are any internet connections
    let has_internet_connections = connections
        .iter()
        .any(|conn| matches!(conn.connection_type, ConnectionType::Internet));
    if has_internet_connections {
        devices.push(NetworkDevice {
            device_id: "internet".to_string(),
            hostname: "🌐 Internet".to_string(),
            device_type: None,
            position: None,
        });
    }

    NetworkTopology {
        devices,
        connections,
        networks: networks.into_values().collect(),
    }
}

#[test]
fn test_topology_without_external_gateways() {
    // Test case: devices with only local routes (no gateways)
    let interface_id = uuid::Uuid::new_v4();
    let device1 = create_test_device_with_routes(
        "device1.local",
        interface_id,
        vec![
            create_test_route("192.168.1.0/24", None, interface_id), // Local route, no gateway
        ],
    );

    let topology = build_test_topology(vec![device1]);

    // Should not create internet node
    assert_eq!(topology.devices.len(), 1);
    assert_eq!(topology.connections.len(), 0);
    assert!(!topology.devices.iter().any(|d| d.device_id == "internet"));
}

#[test]
fn test_topology_with_internal_gateway() {
    // Test case: gateway that points to another discovered device
    let interface_id1 = uuid::Uuid::new_v4();
    let interface_id2 = uuid::Uuid::new_v4();
    let device1 = create_test_device_with_routes(
        "device1.local",
        interface_id1,
        vec![
            create_test_route("0.0.0.0/0", Some("192.168.1.2"), interface_id1), // Default route via device2
        ],
    );

    let mut device2 = create_test_device_with_routes("device2.local", interface_id2, vec![]);
    // Add interface with the gateway IP
    device2.device.interfaces.push(Interface::new(
        uuid::Uuid::new_v4(),
        "eth1".to_string(),
        vec![],
        vec![InterfaceAddress::new(
            IpAddr::from_str("192.168.1.2").unwrap(),
            24,
        )], // Gateway IP
        InterfaceType::Ethernet,
        None,
    ));

    let topology = build_test_topology(vec![device1, device2]);

    // Should create connection between devices, but no internet node
    assert_eq!(topology.devices.len(), 2);
    assert_eq!(topology.connections.len(), 1);
    assert!(!topology.devices.iter().any(|d| d.device_id == "internet"));

    let connection = &topology.connections[0];
    assert_eq!(connection.from, "device1.local");
    assert_eq!(connection.to, "device2.local");
    assert!(matches!(
        connection.connection_type,
        ConnectionType::Gateway
    ));
}

#[test]
fn test_topology_with_external_gateway() {
    // Test case: gateway that points to external internet
    let interface_id = uuid::Uuid::new_v4();
    let device1 = create_test_device_with_routes(
        "device1.local",
        interface_id,
        vec![
            create_test_route("0.0.0.0/0", Some("203.0.113.1"), interface_id), // Default route via internet
        ],
    );

    let topology = build_test_topology(vec![device1]);

    // Should create internet node and connection
    assert_eq!(topology.devices.len(), 2); // device1 + internet
    assert_eq!(topology.connections.len(), 1);

    // Check internet node exists
    let internet_node = topology.devices.iter().find(|d| d.device_id == "internet");
    assert!(internet_node.is_some());
    assert_eq!(internet_node.unwrap().hostname, "🌐 Internet");
    assert!(internet_node.unwrap().device_type.is_none());

    // Check connection to internet
    let connection = &topology.connections[0];
    assert_eq!(connection.from, "device1.local");
    assert_eq!(connection.to, "internet");
    assert_eq!(connection.interface_to, Some("203.0.113.1".to_string()));
    assert!(matches!(
        connection.connection_type,
        ConnectionType::Internet
    ));
}

#[test]
fn test_topology_with_multiple_external_gateways() {
    // Test case: multiple devices with different external gateways
    let interface_id1 = uuid::Uuid::new_v4();
    let interface_id2 = uuid::Uuid::new_v4();
    let device1 = create_test_device_with_routes(
        "device1.local",
        interface_id1,
        vec![
            create_test_route("0.0.0.0/0", Some("203.0.113.1"), interface_id1), // Default route
        ],
    );

    let device2 = create_test_device_with_routes(
        "device2.local",
        interface_id2,
        vec![
            create_test_route("10.0.0.0/8", Some("203.0.113.2"), interface_id2), // Specific route via different gateway
        ],
    );

    let topology = build_test_topology(vec![device1, device2]);

    // Should create one internet node with multiple connections
    assert_eq!(topology.devices.len(), 3); // device1 + device2 + internet
    assert_eq!(topology.connections.len(), 2);

    // Check internet node exists
    assert!(topology.devices.iter().any(|d| d.device_id == "internet"));

    // Check both connections go to internet
    let internet_connections: Vec<_> = topology
        .connections
        .iter()
        .filter(|c| c.to == "internet")
        .collect();
    assert_eq!(internet_connections.len(), 2);

    let from_devices: Vec<&String> = internet_connections.iter().map(|c| &c.from).collect();
    assert!(from_devices.contains(&&"device1.local".to_string()));
    assert!(from_devices.contains(&&"device2.local".to_string()));
}

#[test]
fn test_topology_mixed_internal_external_gateways() {
    // Test case: mix of internal and external gateways
    let interface_id1 = uuid::Uuid::new_v4();
    let interface_id2 = uuid::Uuid::new_v4();
    let device1 = create_test_device_with_routes(
        "device1.local",
        interface_id1,
        vec![
            create_test_route("0.0.0.0/0", Some("192.168.1.2"), interface_id1), // Internal gateway
            create_test_route("8.8.8.8/32", Some("203.0.113.1"), interface_id1), // External gateway
        ],
    );

    let mut device2 = create_test_device_with_routes("device2.local", interface_id2, vec![]);
    device2.device.interfaces.push(Interface::new(
        uuid::Uuid::new_v4(),
        "eth1".to_string(),
        vec![],
        vec![InterfaceAddress::new(
            IpAddr::from_str("192.168.1.2").unwrap(),
            24,
        )], // Internal gateway IP
        InterfaceType::Ethernet,
        None,
    ));

    let topology = build_test_topology(vec![device1, device2]);

    // Should create internet node + both devices
    assert_eq!(topology.devices.len(), 3); // device1 + device2 + internet
    assert_eq!(topology.connections.len(), 2);

    // Check we have one internal connection and one internet connection
    let internal_connections = topology
        .connections
        .iter()
        .filter(|c| matches!(c.connection_type, ConnectionType::Gateway))
        .count();
    let internet_connections = topology
        .connections
        .iter()
        .filter(|c| matches!(c.connection_type, ConnectionType::Internet))
        .count();

    assert_eq!(internal_connections, 1);
    assert_eq!(internet_connections, 1);
}

#[test]
fn test_topology_with_cdp_peer_relationships() {
    // Test case: CDP peer relationships between devices
    let interface_id1 = uuid::Uuid::new_v4();
    let interface_id2 = uuid::Uuid::new_v4();

    // Create first device with CDP peers
    let mut device1 = Device::new(
        "device1.local".to_string(),
        Some("Test Device 1".to_string()),
        Owner::Named("test".to_string()),
        DeviceType::Switch,
    );

    let mut interface1 = Interface::new(
        interface_id1,
        "GigabitEthernet0/1".to_string(),
        vec![],
        vec![InterfaceAddress::new(
            IpAddr::from_str("192.168.1.1").unwrap(),
            24,
        )],
        InterfaceType::Ethernet,
        None,
    );

    // Add MAC address and peer relationship
    interface1.mac_address = Some(MacAddress::from_str("00:11:22:33:44:55").unwrap());
    let mut peers = HashMap::new();
    peers.insert(PeerConnection::Untagged, vec![interface_id2]);
    interface1.peers = peers;
    device1.interfaces.push(interface1);

    // Create second device with reciprocal CDP peer
    let mut device2 = Device::new(
        "device2.local".to_string(),
        Some("Test Device 2".to_string()),
        Owner::Named("test".to_string()),
        DeviceType::Switch,
    );

    let mut interface2 = Interface::new(
        interface_id2,
        "GigabitEthernet0/2".to_string(),
        vec![],
        vec![InterfaceAddress::new(
            IpAddr::from_str("192.168.1.2").unwrap(),
            24,
        )],
        InterfaceType::Ethernet,
        None,
    );

    // Add MAC address and peer relationship
    interface2.mac_address = Some(MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap());
    let mut peers2 = HashMap::new();
    peers2.insert(PeerConnection::Untagged, vec![interface_id1]);
    interface2.peers = peers2;
    device2.interfaces.push(interface2);

    // Create device states
    let device_state1 = DeviceState {
        device: device1,
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        config_hash: 12345u64,
    };

    let device_state2 = DeviceState {
        device: device2,
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        config_hash: 67890u64,
    };

    // Store device IDs before moving the device states
    let device1_id = device_state1.device.device_id;
    let device2_id = device_state2.device.device_id;

    let topology = build_test_topology(vec![device_state1, device_state2]);

    // Should create CDP connections between devices
    assert_eq!(topology.devices.len(), 2);
    assert_eq!(topology.connections.len(), 2); // Bidirectional CDP connections

    // Check CDP connections
    let cdp_connections: Vec<_> = topology
        .connections
        .iter()
        .filter(|c| matches!(c.connection_type, ConnectionType::CDP))
        .collect();
    assert_eq!(cdp_connections.len(), 2);

    // Verify bidirectional connections (check device IDs, not hostnames)
    let device1_id_str = device1_id.to_string();
    let device2_id_str = device2_id.to_string();
    let from_devices: Vec<&String> = cdp_connections.iter().map(|c| &c.from).collect();
    assert!(from_devices.contains(&&device1_id_str) && from_devices.contains(&&device2_id_str));

    // Check interface information is preserved
    assert!(
        cdp_connections[0]
            .interface_from
            .contains("GigabitEthernet")
    );
    assert!(cdp_connections[0].interface_from.contains("CDP"));
}

#[test]
fn test_topology_with_vlan_cdp_relationships() {
    // Test case: CDP peer relationships with VLAN tags
    let interface_id1 = uuid::Uuid::new_v4();
    let interface_id2 = uuid::Uuid::new_v4();

    // Create device with VLAN-tagged CDP peer
    let mut device1 = Device::new(
        "switch1.local".to_string(),
        Some("Test Switch 1".to_string()),
        Owner::Named("test".to_string()),
        DeviceType::Switch,
    );

    let mut interface1 = Interface::new(
        interface_id1,
        "eth0.100".to_string(),
        vec![100],
        vec![InterfaceAddress::new(
            IpAddr::from_str("192.168.100.1").unwrap(),
            24,
        )],
        InterfaceType::Ethernet,
        None,
    );

    // Add VLAN-tagged peer relationship
    interface1.mac_address = Some(MacAddress::from_str("00:11:22:33:44:55").unwrap());
    let mut peers = HashMap::new();
    peers.insert(PeerConnection::Vlan(100), vec![interface_id2]);
    interface1.peers = peers;
    device1.interfaces.push(interface1);

    // Create second device
    let mut device2 = Device::new(
        "switch2.local".to_string(),
        Some("Test Switch 2".to_string()),
        Owner::Named("test".to_string()),
        DeviceType::Switch,
    );

    let mut interface2 = Interface::new(
        interface_id2,
        "eth0.100".to_string(),
        vec![100],
        vec![InterfaceAddress::new(
            IpAddr::from_str("192.168.100.2").unwrap(),
            24,
        )],
        InterfaceType::Ethernet,
        None,
    );

    interface2.mac_address = Some(MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap());
    let mut peers2 = HashMap::new();
    peers2.insert(PeerConnection::Vlan(100), vec![interface_id1]);
    interface2.peers = peers2;
    device2.interfaces.push(interface2);

    // Create device states
    let device_state1 = DeviceState {
        device: device1,
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        config_hash: 12345u64,
    };

    let device_state2 = DeviceState {
        device: device2,
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        config_hash: 67890u64,
    };

    let topology = build_test_topology(vec![device_state1, device_state2]);

    // Should create VLAN-tagged CDP connections
    assert_eq!(topology.devices.len(), 2);
    assert_eq!(topology.connections.len(), 2);

    // Check VLAN CDP connections
    let vlan_cdp_connections: Vec<_> = topology
        .connections
        .iter()
        .filter(|c| {
            matches!(c.connection_type, ConnectionType::CDP)
                && c.interface_from.contains("CDP-VLAN100")
        })
        .collect();
    assert_eq!(vlan_cdp_connections.len(), 2);
}

#[tokio::test]
async fn test_live_topology_has_cdp_connections() {
    // Integration test to verify our topology shows CDP connections
    // This test uses test device configuration and state files

    use crate::config::AppConfig;
    use std::sync::Arc;

    // Load the test configuration
    let config = AppConfig::load_from_file("devices.test.json").expect(
        "Failed to load devices.test.json - make sure you run this test from the project root",
    );

    let app_state = AppState {
        config: Arc::new(config),
    };

    // Get the topology using our web API function
    let result = crate::web::get_network_topology(axum::extract::State(app_state)).await;
    assert!(result.is_ok(), "Should successfully get network topology");

    let topology = result.unwrap().0;

    // Verify we have the expected devices
    assert!(
        !topology.devices.is_empty(),
        "Should have devices in topology"
    );

    // Look for CDP connections between our test devices
    let cdp_connections: Vec<_> = topology
        .connections
        .iter()
        .filter(|c| matches!(c.connection_type, ConnectionType::CDP))
        .collect();

    // We should have at least some CDP connections if neighbor discovery worked
    assert!(
        !cdp_connections.is_empty(),
        "Should have CDP connections in topology"
    );

    // Print the connections for debugging
    println!("Found {} CDP connections:", cdp_connections.len());
    for conn in &cdp_connections {
        println!(
            "  {} -> {}: {} -> {}",
            conn.from,
            conn.to,
            conn.interface_from,
            conn.interface_to.as_deref().unwrap_or("unknown")
        );
    }

    // Look specifically for connections involving our test devices
    let has_mikrotik_cisco_connection = cdp_connections.iter().any(|conn| {
        (conn.interface_from.contains("sfp-sfpplus1")
            || conn.interface_from.contains("bridge")
            || conn.interface_from.contains("ether1"))
            && conn
                .interface_to
                .as_ref()
                .is_some_and(|iface| iface.contains("TenGigabitEthernet"))
    });

    assert!(
        has_mikrotik_cisco_connection,
        "Should have CDP connection between MikroTik (sfp-sfpplus1/bridge/ether1) and Cisco (TenGigabitEthernet) devices. Found connections: {:#?}",
        cdp_connections
    );
}
