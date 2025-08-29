use std::{net::SocketAddr, time::Duration};

use trailfinder::{
    config::{AppConfig, DeviceConfig},
    ssh::{DeviceIdentifier, SshClient},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = "devices.json";

    // Load config file, only create if it doesn't exist
    let mut app_config = match AppConfig::load_from_file(config_path) {
        Ok(config) => {
            println!("Loaded configuration from {}", config_path);
            config
        }
        Err(e) => {
            // Check if file exists but has errors vs doesn't exist
            if std::path::Path::new(config_path).exists() {
                eprintln!("❌ Error loading existing config file '{}': {}", config_path, e);
                eprintln!("💡 Please check the file for JSON syntax errors or permission issues.");
                eprintln!("📄 You can validate JSON at: https://jsonlint.com/");
                return Err(format!("Config file exists but cannot be loaded: {}", e).into());
            } else {
                println!("📄 Config file '{}' not found, creating default configuration", config_path);
                let config = AppConfig::default();
                config.save_to_file(config_path)?;
                println!("✅ Created default config at '{}' - please edit it to add your devices", config_path);
                config
            }
        }
    };

    println!(
        "Found {} devices in configuration",
        app_config.devices.len()
    );

    // Process devices that need identification
    let devices_to_identify: Vec<String> = app_config
        .devices
        .keys()
        .filter(|hostname| app_config.needs_identification(hostname))
        .cloned()
        .collect();

    if devices_to_identify.is_empty() {
        println!("All devices are already identified and up to date");
        return Ok(());
    }

    println!("Identifying {} devices...", devices_to_identify.len());

    for hostname in devices_to_identify {
        println!("Processing device: {}", hostname);

        if let Some(device_config) = app_config.get_device(&hostname).cloned() {
            match identify_device(&device_config, &app_config) {
                Ok((brand, device_type)) => {
                    println!("  Identified as {:?} {:?}", brand, device_type);
                    app_config.update_device_identification(&hostname, brand, device_type)?;
                }
                Err(e) => {
                    println!("  Failed to identify: {}", e);
                }
            }
        }
    }

    // Save updated configuration
    app_config.save_to_file(config_path)?;
    println!("Updated configuration saved to {}", config_path);

    Ok(())
}

fn identify_device(
    device_config: &DeviceConfig,
    app_config: &AppConfig,
) -> Result<(trailfinder::config::DeviceBrand, trailfinder::DeviceType), Box<dyn std::error::Error>>
{
    // Use IP address if provided, otherwise resolve hostname
    let socket_addr = if let Some(ip) = device_config.ip_address {
        SocketAddr::new(ip, device_config.ssh_port.get())
    } else {
        // Resolve hostname to IP
        use std::net::ToSocketAddrs;
        let host_port = format!("{}:{}", device_config.hostname, device_config.ssh_port.get());
        let mut addrs = host_port.to_socket_addrs()
            .map_err(|e| format!("Failed to resolve hostname '{}': {}", device_config.hostname, e))?;
        addrs.next()
            .ok_or_else(|| format!("No IP address found for hostname '{}'", device_config.hostname))?
    };
    let timeout = Duration::from_secs(30);

    println!("  Connecting via SSH...");

    // Try SSH config first, then fall back to manual config
    let mut ssh_client =
        match SshClient::connect_with_ssh_config(&device_config.hostname, socket_addr, timeout) {
            Ok(client) => {
                println!("  Connected using SSH config");
                client
            }
            Err(e) => {
                println!("  SSH config failed ({}), trying manual config...", e);

                let username = device_config
                    .ssh_username
                    .as_deref()
                    .ok_or("No SSH username configured")?;

                let password = std::env::var("SSH_PASSWORD").ok();
                let key_path = device_config.ssh_key_path.as_deref();

                SshClient::connect(
                    socket_addr,
                    username,
                    password.as_deref(),
                    key_path,
                    app_config.use_ssh_agent.unwrap_or(true), // Default to true
                    timeout,
                )?
            }
        };

    let (brand, device_type) = DeviceIdentifier::identify_device(&mut ssh_client)?;

    Ok((brand, device_type))
}
