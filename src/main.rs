use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use clap::{Parser, Subcommand};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use trailfinder::{
    DeviceType, TrailFinderError,
    brand::interrogate_device_by_brand,
    config::{AppConfig, DeviceBrand, DeviceConfig, DeviceState},
    ssh::{DeviceIdentifier, SshClient},
    web::web_server_command,
};
use uuid::Uuid;

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

async fn main_func() -> Result<(), Box<dyn std::error::Error>> {
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
                .with_target(cli.debug)
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
            web_server_command(&app_config, &address, port)
                .await
                .map_err(|err| Box::new(std::io::Error::other(err.to_string())))?;
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

        match identify_and_interrogate_device(device_config.clone())
            .await
        {
            Ok((device_id, brand, device_type, device_state)) => {
                info!("{device_id} Identified as {:?} {:?}", brand, device_type);

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
                    Ok(()) => info!("Device {hostname} state saved successfully"),
                    Err(e) => warn!("Failed to save device {hostname} state: {}", e),
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

    // Resolve all neighbor relationships after device identification
    let device_states = app_config
        .load_all_device_states()
        .map_err(|e| TrailFinderError::Generic(e.to_string()))?;
    if !device_states.is_empty() {
        let mut device_states_vec = device_states.into_values().collect::<Vec<_>>();
        match trailfinder::neighbor_resolution::resolve_all_neighbor_relationships(
            &mut device_states_vec,
        ) {
            Ok(relationships) => {
                if relationships > 0 {
                    info!("Resolved {} neighbor relationships", relationships);
                    // Save updated device states with peer relationships
                    for device_state in device_states_vec {
                        if let Err(e) = app_config
                            .save_device_state(&device_state.device.hostname, &device_state)
                        {
                            warn!(
                                "Failed to save updated device state for {}: {}",
                                device_state.device.hostname, e
                            );
                        }
                    }
                } else {
                    info!("No neighbor relationships found to resolve");
                }
            }
            Err(e) => {
                warn!("Failed to resolve neighbor relationships: {}", e);
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
) -> Result<(), TrailFinderError> {
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

    let mut tasks = JoinSet::new();

    for hostname in devices_to_update {
        info!("Updating device: {}", hostname);
        if let Some(device_config) = app_config.get_device(&hostname).cloned() {
            tasks.spawn(identify_and_interrogate_device(device_config));
        }
    }

    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(Ok((device_id, brand, device_type, device_state))) => {
                let hostname = match app_config.get_hostname_by_id(device_id) {
                    Some(val) => val,
                    None => {
                        error!("Failed to get hostname for device ID {}", device_id);
                        return Err(TrailFinderError::NotFound(format!(
                            "Couldn't find device with ID {}",
                            device_id
                        )));
                    }
                };
                info!(
                    "Updated {hostname} {brand} {device_type} - {} interfaces, {} routes",
                    device_state.device.interfaces.len(),
                    device_state.device.routes.len()
                );

                // Update device identification (in case type changed)
                app_config.update_device_identification(&hostname, brand, device_type)?;

                // Save updated device state
                match app_config.save_device_state(&hostname, &device_state) {
                    Ok(()) => info!("Device state updated successfully for {hostname}"),
                    Err(e) => warn!("Failed to save updated device state for {hostname}: {e}"),
                }
            }
            Err(e) => {
                error!("Failed to update {}", e);
            }
            Ok(Err(e)) => return Err(e),
        }
    }

    // Resolve all neighbor relationships after device updates
    let device_states = app_config
        .load_all_device_states()
        .map_err(|e| TrailFinderError::Generic(e.to_string()))?;
    if !device_states.is_empty() {
        let mut device_states_vec = device_states.into_values().collect::<Vec<_>>();
        match trailfinder::neighbor_resolution::resolve_all_neighbor_relationships(
            &mut device_states_vec,
        ) {
            Ok(relationships) => {
                if relationships > 0 {
                    info!("Resolved {} neighbor relationships", relationships);
                    // Save updated device states with peer relationships
                    for device_state in device_states_vec {
                        if let Err(e) = app_config
                            .save_device_state(&device_state.device.hostname, &device_state)
                        {
                            warn!(
                                "Failed to save updated device state for {}: {}",
                                device_state.device.hostname, e
                            );
                        }
                    }
                } else {
                    info!("No neighbor relationships found to resolve");
                }
            }
            Err(e) => {
                warn!("Failed to resolve neighbor relationships: {}", e);
            }
        }
    }

    // Save updated configuration
    app_config.save_to_file(config_path)?;
    info!("Updated configuration saved to {}", config_path);

    Ok(())
}

async fn identify_and_interrogate_device(
    device_config: DeviceConfig,
) -> Result<(Uuid, DeviceBrand, DeviceType, DeviceState), TrailFinderError> {
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
            TrailFinderError::NotFound(format!(
                "Failed to resolve hostname '{}': {}",
                device_config.hostname, e
            ))
        })?;
        addrs.next().ok_or_else(|| {
            TrailFinderError::NotFound(format!(
                "No IP address found for hostname '{}'",
                device_config.hostname
            ))
        })?
    };
    let timeout = Duration::from_secs(30);

    debug!("Connecting via SSH using processed device config...");

    // Use the new method that leverages preprocessed SSH configuration
    let mut ssh_client = SshClient::connect_with_device_config(
        &device_config,
        socket_addr,
        timeout,
    )
    .await
    .map_err(|err| TrailFinderError::Generic(err.to_string()))?;

    let (brand, device_type) = DeviceIdentifier::identify_device(&mut ssh_client).await?;

    info!(
        "Interrogating device {} configuration... for brand {brand}",
        device_config.hostname
    );

    // Interrogate device using trait-based approach
    let device_state =
        interrogate_device_by_brand(brand.clone(), &mut ssh_client, &device_config, device_type)
            .await?;

    Ok((device_config.device_id, brand, device_type, device_state))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(
            std::thread::available_parallelism()
                .map(|t| t.get())
                .unwrap_or_else(|_e| {
                    eprintln!("WARNING: Unable to read number of available CPUs, defaulting to 4");
                    4
                }),
        )
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { main_func().await })
}
