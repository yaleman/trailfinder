use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use clap::{Parser, Subcommand};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use trailfinder::{
    DeviceType,
    brand::interrogate_device_by_brand,
    config::{AppConfig, DeviceBrand, DeviceConfig, DeviceState},
    ssh::{DeviceIdentifier, SshClient},
    web::{AppState, create_router},
};

/// Trailfinder - Network device discovery and configuration parsing tool
#[derive(Parser)]
#[command(name = "trailfinder")]
#[command(about = "A CLI tool for network device discovery and state management")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Enable debug logging (shows detailed SSH authentication and parsing information)
    #[arg(short, long, global = true)]
    debug: bool,

    /// Path to devices configuration file
    #[arg(
        short = 'c',
        long = "config",
        default_value = "devices.json",
        global = true
    )]
    config_path: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start web server for network topology visualization
    Web {
        /// Port to bind the web server to
        #[arg(short, long, default_value = "3000")]
        port: u16,
        /// Address to bind the web server to
        #[arg(short, long, default_value = "127.0.0.1")]
        address: String,
    },
    /// Identify new devices that haven't been processed yet (default behavior)
    Identify {
        /// Specific hostname to identify and add to config if not present
        hostname: Option<String>,
        /// SSH username to use for connection
        #[arg(short, long)]
        username: Option<String>,
        /// SSH key file path to use for authentication
        #[arg(short, long)]
        keyfile: Option<String>,
        /// IP address to use for connection
        #[arg(short, long)]
        ip_address: Option<String>,
    },
    /// Update device state from live devices, forcing fresh data collection
    Update {
        /// Specific device hostnames to update (updates all if none specified)
        devices: Vec<String>,
    },
}

async fn web_server_command(
    app_config: &AppConfig,
    address: &str,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    info!("Starting web server on {}:{}", address, port);

    let state = AppState {
        config: Arc::new(app_config.clone()),
    };

    let app = create_router(state);

    let bind_addr = format!("{}:{}", address, port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    info!("🌐 Web UI available at: http://{}", bind_addr);
    info!("📊 API documentation at: http://{}/api", bind_addr);
    info!("Press Ctrl+C to stop the server");

    axum::serve(listener, app).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let cli = Cli::parse();

    // Initialize tracing subscriber with CLI options
    let env_filter_str = if cli.debug { "debug" } else { "info" };

    let env_filter = EnvFilter::new(format!(
        "{env_filter_str},russh::client=info,russh::sshbuffer=info"
    ));

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_level(true),
        )
        .with(env_filter)
        .init();

    let config_path = &cli.config_path;

    // Load config file, only create if it doesn't exist
    let mut app_config = match AppConfig::load_from_file(config_path) {
        Ok(config) => {
            info!("Loaded configuration from {}", config_path);
            config
        }
        Err(e) => {
            // Check if file exists but has errors vs doesn't exist
            if std::path::Path::new(config_path).exists() {
                error!(
                    "Error loading existing config file '{}': {}",
                    config_path, e
                );
                error!("💡 Please check the file for JSON syntax errors or permission issues.");
                error!("📄 You can validate JSON at: https://jsonlint.com/");
                return Err(format!("Config file exists but cannot be loaded: {}", e).into());
            } else {
                info!(
                    "Config file '{}' not found, creating default configuration",
                    config_path
                );
                let config = AppConfig::default();
                config.save_to_file(config_path)?;
                info!(
                    "✅ Created default config at '{}' - please edit it to add your devices",
                    config_path
                );
                config
            }
        }
    };

    info!(
        "Found {} devices in configuration",
        app_config.devices.len()
    );

    // Handle different commands
    match cli.command.unwrap_or(Commands::Identify {
        hostname: None,
        username: None,
        keyfile: None,
        ip_address: None,
    }) {
        Commands::Web { port, address } => {
            return web_server_command(&app_config, &address, port).await;
        }
        Commands::Identify {
            hostname,
            username,
            keyfile,
            ip_address,
        } => {
            identify_command(
                &mut app_config,
                config_path,
                hostname,
                username,
                keyfile,
                ip_address,
            )
            .await?;
        }
        Commands::Update { devices } => {
            update_command(&mut app_config, config_path, devices).await?;
        }
    }

    Ok(())
}

async fn identify_command(
    app_config: &mut AppConfig,
    config_path: &str,
    target_hostname: Option<String>,
    username: Option<String>,
    keyfile: Option<String>,
    ip_address: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (devices_to_identify, new_device_hostname): (Vec<String>, Option<String>) =
        if let Some(hostname) = target_hostname {
            // If a specific hostname is provided, check if it exists in config
            if app_config.get_device(&hostname).is_none() {
                info!(
                    "Device '{}' not found in config, will add after successful identification",
                    hostname
                );
                // Don't add to config yet - wait for successful identification
                (vec![hostname.clone()], Some(hostname))
            } else {
                // Device exists in config, process normally
                (vec![hostname], None)
            }
        } else {
            // Process devices that need identification
            let devices: Vec<String> = app_config
                .devices
                .iter()
                .filter(|device| app_config.needs_identification(&device.hostname))
                .map(|device| device.hostname.clone())
                .collect();

            if devices.is_empty() {
                info!("All devices are already identified and up to date");
                return Ok(());
            }

            (devices, None)
        };

    info!("Identifying {} device(s)...", devices_to_identify.len());

    for hostname in devices_to_identify {
        info!("Processing device: {}", hostname);

        // For new devices, create a temporary config for identification
        let mut device_config = if let Some(ref new_hostname) = new_device_hostname {
            if hostname == *new_hostname {
                // Create temporary device config for identification
                DeviceConfig {
                    hostname: hostname.clone(),
                    ..Default::default()
                }
            } else {
                app_config.get_device(&hostname).cloned().unwrap()
            }
        } else {
            app_config.get_device(&hostname).cloned().unwrap()
        };

        // Apply CLI-provided SSH parameters (override config values)
        if let Some(ref cli_username) = username {
            device_config.ssh_username = Some(cli_username.clone());
        }
        if let Some(ref cli_keyfile) = keyfile {
            device_config.ssh_key_path = Some(cli_keyfile.clone());
        }
        if let Some(ref cli_ip_address) = ip_address {
            match cli_ip_address.parse::<IpAddr>() {
                Ok(ip) => {
                    device_config.ip_address = Some(ip);
                }
                Err(e) => {
                    return Err(format!("Invalid IP address '{}': {}", cli_ip_address, e).into());
                }
            }
        }

        match identify_and_interrogate_device(&device_config, app_config).await {
            Ok((brand, device_type, device_state)) => {
                info!("Identified as {:?} {:?}", brand, device_type);

                // If this is a new device, add it to config now that identification succeeded
                if let Some(ref new_hostname) = new_device_hostname
                    && hostname == *new_hostname
                {
                    info!(
                        "Adding '{}' to configuration after successful identification",
                        hostname
                    );
                    app_config.add_device(device_config);
                }

                app_config.update_device_identification(&hostname, brand, device_type)?;

                // Save device state
                match app_config.save_device_state(&hostname, &device_state) {
                    Ok(()) => info!("Device state saved successfully"),
                    Err(e) => warn!("Failed to save device state: {}", e),
                }
            }
            Err(e) => {
                error!("Failed to identify/interrogate {}: {}", hostname, e);
                // If this was a new device that failed identification, don't add it to config
                if let Some(ref new_hostname) = new_device_hostname
                    && hostname == *new_hostname
                {
                    info!(
                        "Not adding '{}' to configuration due to identification failure",
                        hostname
                    );
                }
            }
        }
    }

    // Save updated configuration
    app_config.save_to_file(config_path)?;
    info!("Updated configuration saved to {}", config_path);

    Ok(())
}

async fn update_command(
    app_config: &mut AppConfig,
    config_path: &str,
    specific_devices: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Determine which devices to update
    let devices_to_update: Vec<String> = if specific_devices.is_empty() {
        // Update all devices
        app_config
            .devices
            .iter()
            .filter(|device| {
                // Skip devices that aren't identified yet (they should use identify command)
                device.brand.is_some() && device.device_type.is_some()
                // Update command always forces update
            })
            .map(|device| device.hostname.clone())
            .collect()
    } else {
        // Update only specified devices
        let mut valid_devices = Vec::new();
        for hostname in specific_devices {
            if let Some(device) = app_config.get_device(&hostname) {
                if device.brand.is_none() || device.device_type.is_none() {
                    warn!(
                        "Device '{}' is not yet identified, use 'identify' command first",
                        hostname
                    );
                    continue;
                }
                // Update command always forces update
                valid_devices.push(hostname);
            } else {
                warn!("Device '{}' not found in configuration", hostname);
            }
        }
        valid_devices
    };

    if devices_to_update.is_empty() {
        info!("No devices found to update");
        return Ok(());
    }

    info!("Updating {} devices...", devices_to_update.len());

    for hostname in devices_to_update {
        info!("Updating device: {}", hostname);

        if let Some(device_config) = app_config.get_device(&hostname).cloned() {
            match identify_and_interrogate_device(&device_config, app_config).await {
                Ok((brand, device_type, device_state)) => {
                    info!(
                        "Updated {:?} {:?} - {} interfaces, {} routes",
                        brand,
                        device_type,
                        device_state.device.interfaces.len(),
                        device_state.device.routes.len()
                    );

                    // Update device identification (in case type changed)
                    app_config.update_device_identification(&hostname, brand, device_type)?;

                    // Save updated device state
                    match app_config.save_device_state(&hostname, &device_state) {
                        Ok(()) => info!("Device state updated successfully"),
                        Err(e) => warn!("Failed to save updated device state: {}", e),
                    }
                }
                Err(e) => {
                    error!("Failed to update {}: {}", hostname, e);
                }
            }
        }
    }

    // Save updated configuration
    app_config.save_to_file(config_path)?;
    info!("Updated configuration saved to {}", config_path);

    Ok(())
}

async fn identify_and_interrogate_device(
    device_config: &DeviceConfig,
    app_config: &AppConfig,
) -> Result<(DeviceBrand, DeviceType, DeviceState), Box<dyn std::error::Error>> {
    // Use IP address if provided, otherwise resolve hostname
    let socket_addr = if let Some(ip) = device_config.ip_address {
        SocketAddr::new(ip, device_config.ssh_port.get())
    } else {
        // Resolve hostname to IP
        use std::net::ToSocketAddrs;
        let host_port = format!(
            "{}:{}",
            device_config.hostname,
            device_config.ssh_port.get()
        );
        let mut addrs = host_port.to_socket_addrs().map_err(|e| {
            format!(
                "Failed to resolve hostname '{}': {}",
                device_config.hostname, e
            )
        })?;
        addrs.next().ok_or_else(|| {
            format!(
                "No IP address found for hostname '{}'",
                device_config.hostname
            )
        })?
    };
    let timeout = Duration::from_secs(30);

    debug!("Connecting via SSH...");

    // Try SSH config first, then fall back to manual config
    let mut ssh_client =
        match SshClient::connect_with_ssh_config(&device_config.hostname, socket_addr, timeout)
            .await
        {
            Ok(client) => {
                debug!("Connected using SSH config");
                client
            }
            Err(e) => {
                debug!("SSH config failed ({}), trying manual config...", e);

                let username = device_config
                    .ssh_username
                    .as_deref()
                    .ok_or("No SSH username configured")?;

                let password = std::env::var("SSH_PASSWORD").ok();
                let key_path = device_config
                    .ssh_key_path
                    .as_deref()
                    .map(shellexpand::tilde);

                // Get passphrase from config or environment variable
                let env_passphrase = std::env::var("SSH_KEY_PASSPHRASE").ok();
                let key_passphrase = device_config
                    .ssh_key_passphrase
                    .as_deref()
                    .or(env_passphrase.as_deref());

                SshClient::connect(
                    socket_addr,
                    username,
                    password.as_deref(),
                    key_path.as_deref(),
                    key_passphrase,
                    app_config.use_ssh_agent.unwrap_or(true), // Default to true
                    timeout,
                )
                .await?
            }
        };

    let (brand, device_type) = DeviceIdentifier::identify_device(&mut ssh_client).await?;

    info!("Interrogating device configuration... for brand {brand}");

    // Interrogate device using trait-based approach
    let device_state =
        interrogate_device_by_brand(brand.clone(), &mut ssh_client, device_config, device_type)
            .await?;

    Ok((brand, device_type, device_state))
}
