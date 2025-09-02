mod browser_integration;
mod playwright_integration;
mod ui_tests;
mod web_tests;

use crate::*;
use std::io::Error;
use std::net::TcpListener;
use std::process::{Child, Command};

/// Handle for managing a ChromeDriver instance
pub struct ChromeDriverHandle {
    pub process: Child,
    pub port: u16,
}

impl ChromeDriverHandle {
    /// Start ChromeDriver on a random available port
    pub fn start() -> Result<Self, Error> {
        // Try to find an available port and start ChromeDriver
        let mut attempts = 0;
        while attempts < 10 {
            let port = find_available_port()?;
            // Start ChromeDriver on that port
            match Command::new("chromedriver")
                .arg(format!("--port={}", port))
                .arg("--allowed-ips=127.0.0.1")
                .spawn()
            {
                Ok(process) => {
                    return Ok(ChromeDriverHandle { process, port });
                }
                Err(e) => {
                    eprintln!("Failed to start chromedriver on port {}: {}", port, e);
                    attempts += 1;
                }
            }
        }

        Err(Error::other(
            "Failed to start chromedriver after 10 attempts",
        ))
    }

    /// Get the WebDriver URL for this ChromeDriver instance
    pub fn webdriver_url(&self) -> String {
        format!("http://localhost:{}", self.port)
    }
}

impl Drop for ChromeDriverHandle {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}

/// Find an available port by binding to localhost:0
fn find_available_port() -> Result<u16, Error> {
    // Use a reasonable range for ChromeDriver ports (avoid system ports)
    for _ in 0..10 {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let port = addr.port();

        // Make sure port is in reasonable range (avoid 0 and system ports)
        if port > 1024 && port < 65535 {
            return Ok(port);
        }
    }

    Err(Error::other("Could not find valid port"))
}

#[test]
fn test_device_identity_tracking() {
    let mut device = Device::new(
        "router.example.com".to_string(),
        Some("Test Router".to_string()),
        Owner::Named("Lab".to_string()),
        DeviceType::Router,
    );

    // Initially no system identity
    assert!(device.system_identity.is_none());

    // Set system identity
    device.system_identity = Some("MyRouter".to_string());
    assert_eq!(device.system_identity, Some("MyRouter".to_string()));
}

#[test]
fn test_find_device_by_hostname_fuzzy_with_identity() {
    use crate::config::DeviceState;

    let device1 = Device::new(
        "router1.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );
    let mut device_state1 = DeviceState::new(device1, "test config");
    device_state1.device.system_identity = Some("CoreRouter".to_string());

    let device2 = Device::new(
        "switch1.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Switch,
    );
    let device_state2 = DeviceState::new(device2, "test config 2");

    let device_states = vec![device_state1, device_state2];

    // Test finding by hostname
    let result = neighbor_resolution::find_device_by_hostname_fuzzy("router1", &device_states);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0);

    // Test finding by system identity
    let result = neighbor_resolution::find_device_by_hostname_fuzzy("CoreRouter", &device_states);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0);

    // Test finding with domain stripping
    let result =
        neighbor_resolution::find_device_by_hostname_fuzzy("router1.example.com", &device_states);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), 0);

    // Test no match
    let result = neighbor_resolution::find_device_by_hostname_fuzzy("nonexistent", &device_states);
    assert!(result.is_none());
}
