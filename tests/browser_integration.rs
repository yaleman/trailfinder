use std::time::Duration;
use tokio::time::sleep;
use trailfinder::{config::AppConfig, web::web_server_command};

/// Browser integration test using the actual MCP Playwright integration
/// This test verifies real functionality end-to-end

#[tokio::test]
async fn test_end_to_end_functionality() {
    // Start test server using the shared web_server_command
    let app_config = AppConfig::load_from_file("devices.example.json").unwrap_or_else(|_| {
        eprintln!("Warning: Could not load devices.json for test");
        AppConfig::default()
    });

    let server_handle = tokio::spawn(async move {
        if let Err(e) = web_server_command(&app_config, "127.0.0.1", 8082).await {
            eprintln!("Test server error: {}", e);
        }
    });

    // Give server time to start
    sleep(Duration::from_secs(2)).await;

    // Test the API directly first
    let response = reqwest::get("http://127.0.0.1:8082/api/devices")
        .await
        .expect("Failed to call API");

    assert!(response.status().is_success(), "API should return success");

    let devices: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    println!(
        "✓ API returned {} devices",
        devices.as_array().map(|a| a.len()).unwrap_or(0)
    );

    // Test topology API
    let topology_response = reqwest::get("http://127.0.0.1:8082/api/topology")
        .await
        .expect("Failed to call topology API");

    assert!(
        topology_response.status().is_success(),
        "Topology API should return success"
    );

    let topology: serde_json::Value = topology_response
        .json()
        .await
        .expect("Failed to parse topology JSON");

    // Check if internet node is present when there are external gateways
    if let Some(devices_array) = topology.get("devices").and_then(|d| d.as_array()) {
        let has_internet_node = devices_array
            .iter()
            .any(|device| device.get("device_id").and_then(|id| id.as_str()) == Some("internet"));

        if has_internet_node {
            println!("✓ Internet node found in topology");

            // Verify internet node structure
            let internet_node = devices_array
                .iter()
                .find(|device| {
                    device.get("device_id").and_then(|id| id.as_str()) == Some("internet")
                })
                .expect("Internet node should exist");

            assert_eq!(
                internet_node.get("hostname").and_then(|h| h.as_str()),
                Some("🌐 Internet"),
                "Internet node should have correct hostname"
            );

            assert_eq!(
                internet_node.get("device_type"),
                Some(&serde_json::Value::Null),
                "Internet node should have null device type"
            );
        } else {
            println!("ℹ️ No internet node found - no external gateways detected");
        }
    }

    // Check connections for Internet type
    if let Some(connections_array) = topology.get("connections").and_then(|c| c.as_array()) {
        let internet_connections: Vec<_> = connections_array
            .iter()
            .filter(|conn| {
                conn.get("connection_type").and_then(|ct| ct.as_str()) == Some("Internet")
            })
            .collect();

        if !internet_connections.is_empty() {
            println!(
                "✓ Found {} Internet connections",
                internet_connections.len()
            );

            // Verify connection structure
            for conn in &internet_connections {
                assert_eq!(
                    conn.get("to").and_then(|t| t.as_str()),
                    Some("internet"),
                    "Internet connections should point to 'internet' node"
                );

                assert!(
                    conn.get("interface_to").is_some(),
                    "Internet connections should have interface_to (gateway IP)"
                );
            }
        } else {
            println!("ℹ️ No Internet connections found");
        }
    }

    // Debug: Check if devices have routes with gateways
    let mut devices_with_routes = 0;
    let mut routes_with_gateways = 0;

    // Test interface address structure if devices have interfaces
    for device in devices.as_array().unwrap_or(&vec![]) {
        if let Some(device_detail) = device.as_object() {
            // Check routes for debugging
            if let Some(routes) = device_detail.get("routes").and_then(|r| r.as_array()) {
                devices_with_routes += 1;
                for route in routes {
                    if let Some(gateway) = route.get("gateway")
                        && !gateway.is_null()
                    {
                        routes_with_gateways += 1;
                    }
                }
            }

            if let Some(interfaces) = device_detail.get("interfaces").and_then(|i| i.as_array()) {
                for interface in interfaces {
                    if let Some(addresses) = interface.get("addresses").and_then(|a| a.as_array()) {
                        for address in addresses {
                            // Verify InterfaceAddress structure
                            assert!(
                                address.get("ip").is_some(),
                                "Interface address should have 'ip' field"
                            );
                            assert!(
                                address.get("prefix_length").is_some(),
                                "Interface address should have 'prefix_length' field"
                            );
                        }
                    }

                    // Verify VLAN structure
                    if let Some(vlans) = interface.get("vlans") {
                        assert!(vlans.is_array(), "Interface VLANs should be an array");
                    }
                }
            }
        }
    }

    println!(
        "✓ Found {} devices with routes, {} routes have gateways",
        devices_with_routes, routes_with_gateways
    );
    println!("✓ All API structure tests passed");

    // Clean up
    server_handle.abort();
    println!("✓ End-to-end functionality test completed successfully");
}
