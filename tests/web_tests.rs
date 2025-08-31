use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use trailfinder::config::DeviceState;
use trailfinder::web::*;
use trailfinder::{
    Device, DeviceType, Interface, InterfaceAddress, InterfaceType, Owner, Route, RouteType,
};

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
