//! CLI Handling module

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use clap::{Parser, Subcommand};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    DeviceType, Owner, TrailFinderError,
    brand::interrogate_device_by_brand,
    config::{AppConfig, DeviceBrand, DeviceConfig, DeviceState},
    network_discovery::{self, ScanConfig},
    pathfind::{PathEndpoint, PathFindRequest, find_path},
    ssh::{DeviceIdentifier, SshClient},
    web::web_server_command,
};
use dialoguer::Confirm;
use uuid::Uuid;

pub const DEFAULT_CONFIG_FILE: &str = "devices.json";

/// Apply CLI SSH parameters to device config without prompting (for runtime use)
fn apply_ssh_params_no_prompts(
    device_config: &mut DeviceConfig,
    username: &Option<String>,
    keyfile: &Option<String>,
    key_passphrase: &Option<String>,
) {
    // Apply CLI username
    if let Some(cli_username) = username {
        device_config.ssh_username = Some(cli_username.clone());
    }

    // Apply CLI keyfile
    if let Some(cli_keyfile) = keyfile {
        let cli_keyfile_path: std::path::PathBuf = cli_keyfile.into();
        device_config
            .ssh_identity_files
            .insert(0, cli_keyfile_path.clone());
        device_config
            .all_ssh_identity_files
            .insert(0, cli_keyfile_path);
    }

    // Apply CLI passphrase
    if let Some(cli_passphrase) = key_passphrase {
        device_config.ssh_key_passphrase = Some(cli_passphrase.clone());
    }
}

/// Prompt to save CLI SSH parameters to device config if they differ from current config
fn prompt_to_save_ssh_params(
    app_config: &mut AppConfig,
    hostname: &str,
    username: &Option<String>,
    keyfile: &Option<String>,
    key_passphrase: &Option<String>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut changes_to_save = Vec::new();
    let current_device = app_config.get_device(hostname);

    // Check if CLI username differs from config
    if let Some(cli_username) = username
        && current_device.is_none_or(|d| d.ssh_username.as_ref() != Some(cli_username))
    {
        changes_to_save.push(format!("username: {}", cli_username));
    }

    // Check if CLI keyfile would be added
    if let Some(cli_keyfile) = keyfile {
        changes_to_save.push(format!("keyfile: {}", cli_keyfile));
    }

    // Check if CLI passphrase differs from config
    if let Some(cli_passphrase) = key_passphrase
        && current_device.is_none_or(|d| d.ssh_key_passphrase.as_ref() != Some(cli_passphrase))
    {
        changes_to_save.push("SSH key passphrase".to_string());
    }

    // Prompt to save changes if any were detected
    if !changes_to_save.is_empty() {
        let change_list = changes_to_save.join(", ");
        let prompt_text = format!(
            "Save SSH configuration changes to device '{}' config?\nChanges: {}",
            hostname, change_list
        );

        if Confirm::new()
            .with_prompt(prompt_text)
            .default(false)
            .interact()
            .unwrap_or(false)
        {
            // Apply the changes to the device config
            if let Some(device) = app_config.get_device_mut(hostname) {
                if let Some(cli_username) = username {
                    device.ssh_username = Some(cli_username.clone());
                }
                if let Some(cli_keyfile) = keyfile {
                    let cli_keyfile_path: std::path::PathBuf = cli_keyfile.into();
                    if !device.ssh_identity_files.contains(&cli_keyfile_path) {
                        device.ssh_identity_files.insert(0, cli_keyfile_path);
                    }
                }
                if let Some(cli_passphrase) = key_passphrase {
                    device.ssh_key_passphrase = Some(cli_passphrase.clone());
                }
            }
            return Ok(true);
        }
    }

    Ok(false)
}

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
        default_value = DEFAULT_CONFIG_FILE,
        global = true
    )]
    config_path: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a device to the configuration
    Add {
        /// Hostname of the device to add
        hostname: String,
        /// IP address to use for connection
        #[arg(short, long)]
        ip_address: Option<String>,
        /// SSH username to use for connection
        #[arg(short, long, env = "USER")]
        username: Option<String>,
        /// SSH key file path to use for authentication
        #[arg(short, long)]
        keyfile: Option<String>,
        /// SSH key passphrase to use for authentication
        #[arg(long, env = "TRAILFINDER_KEY_PASSPHRASE")]
        key_passphrase: Option<String>,
        /// SSH port to use for connection
        #[arg(short, long, default_value = "22")]
        port: u16,
        /// Device owner name
        #[arg(short, long)]
        owner: Option<String>,
        /// Optional notes about the device
        #[arg(short, long)]
        notes: Option<String>,
        /// Automatically identify device after adding
        #[arg(long)]
        identify: bool,
    },
    /// Start web server for network topology visualization
    Web {
        /// Port to bind the web server to
        #[arg(short, long, default_value = "8000")]
        port: u16,
        /// Address to bind the web server to
        #[arg(short, long, default_value = "127.0.0.1")]
        address: String,
        /// TLS certificate file path for HTTPS
        #[arg(long, env = "TRAILFINDER_TLS_CERT_FILE")]
        tls_cert: Option<String>,
        /// TLS private key file path for HTTPS
        #[arg(long, env = "TRAILFINDER_TLS_KEY_FILE")]
        tls_key: Option<String>,
        /// TLS hostname override (if not specified, extracted from certificate)
        #[arg(long, env = "TRAILFINDER_TLS_HOSTNAME")]
        tls_hostname: Option<String>,
    },
    /// Identify new devices that haven't been processed yet (default behavior)
    Identify {
        /// Specific hostname to identify and add to config if not present
        hostname: Option<String>,
        /// SSH username to use for connection
        #[arg(short, long, env = "USER")]
        username: Option<String>,
        /// SSH key file path to use for authentication
        #[arg(short, long)]
        keyfile: Option<String>,
        /// SSH key passphrase to use for authentication
        #[arg(long, env = "TRAILFINDER_KEY_PASSPHRASE")]
        key_passphrase: Option<String>,
        /// IP address to use for connection
        #[arg(short, long)]
        ip_address: Option<String>,
        /// Use cached command responses instead of executing commands over SSH
        #[arg(long)]
        cached: bool,
    },
    /// Update device state from live devices, forcing fresh data collection
    Update {
        /// Specific device hostnames to update (updates all if none specified)
        devices: Vec<String>,
        /// SSH username to use for connection
        #[arg(short, long, env = "USER")]
        username: Option<String>,
        /// SSH key file path to use for authentication
        #[arg(short, long)]
        keyfile: Option<String>,
        /// SSH key passphrase to use for authentication
        #[arg(long, env = "TRAILFINDER_KEY_PASSPHRASE")]
        key_passphrase: Option<String>,
        /// Use cached command responses instead of executing commands over SSH
        #[arg(long)]
        cached: bool,
    },
    /// Find network path between two IP addresses
    Pathfind {
        /// Source IP address
        source_ip: String,
        /// Destination IP address or network (e.g., 192.168.1.1 or 10.0.0.0/24)
        destination_ip: String,
        /// Source device hostname
        #[arg(long)]
        source_device: Option<String>,
        /// Source interface name
        #[arg(long)]
        source_interface: Option<String>,
        /// Source VLAN ID
        #[arg(long)]
        source_vlan: Option<u16>,
        /// Destination device hostname
        #[arg(long)]
        dest_device: Option<String>,
        /// Destination interface name
        #[arg(long)]
        dest_interface: Option<String>,
        /// Destination VLAN ID
        #[arg(long)]
        dest_vlan: Option<u16>,
    },
    /// Show the parsed application configuration
    ConfigDump {
        /// Pretty print the JSON output
        #[arg(short, long)]
        pretty: bool,
    },
    /// Remove a device from configuration
    Remove {
        /// Hostname of device to remove
        hostname: String,
        /// Also remove device state file
        #[arg(long)]
        delete_state: bool,
    },
    /// Discover devices by scanning network targets
    Scan {
        /// IP addresses, hostnames, or CIDR networks to scan (e.g. 192.168.1.1, router.local, or 10.0.0.0/24)
        targets: Vec<String>,
        /// SSH port to test (default: 22)
        #[arg(short, long, default_value = "22")]
        port: u16,
        /// SSH username for identification attempts (defaults to ~/.ssh/config or $USER)
        #[arg(short, long, env = "USER")]
        username: Option<String>,
        /// SSH key file for authentication (defaults to ~/.ssh/config identity files)
        #[arg(short, long, env = "TRAILFINDER_KEYFILE")]
        keyfile: Option<String>,
        /// SSH key passphrase to use for authentication
        #[arg(long, env = "TRAILFINDER_KEY_PASSPHRASE")]
        key_passphrase: Option<String>,
        /// Connection timeout in seconds
        #[arg(short, long, default_value = "5")]
        timeout: u64,
        /// Add discovered devices to configuration automatically
        #[arg(long)]
        add: bool,
        /// Use cached command responses instead of executing commands over SSH
        #[arg(long)]
        cached: bool,
    },
}

pub async fn main_func() -> Result<(), Box<dyn std::error::Error>> {
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
                .with_writer(std::io::stderr)
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
            info!("Loaded configuration from {}", config_path.display());
            config
        }
        Err(e) => {
            // Check if file exists but has errors vs doesn't exist
            if config_path.exists() {
                error!(
                    "Error loading existing config file '{}': {}",
                    config_path.display(),
                    e
                );
                error!("💡 Please check the file for JSON syntax errors or permission issues.");
                error!("📄 You can validate JSON at: https://jsonlint.com/");
                return Err(format!("Config file exists but cannot be loaded: {}", e).into());
            } else {
                info!(
                    "Config file '{}' not found, creating default configuration",
                    config_path.display()
                );
                let config = AppConfig::default();
                config.save_to_file(config_path)?;
                info!(
                    "✅ Created default config at '{}' - please edit it to add your devices",
                    config_path.display()
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
    match cli.command {
        Commands::Add {
            hostname,
            ip_address,
            username,
            keyfile,
            key_passphrase,
            port,
            owner,
            notes,
            identify,
        } => {
            let params = AddDeviceParams {
                hostname: &hostname,
                ip_address: &ip_address,
                username: &username,
                keyfile: &keyfile,
                key_passphrase: &key_passphrase,
                port,
                owner: &owner,
                notes: &notes,
                identify,
            };
            add_command(&mut app_config, config_path, &params).await?;
        }
        Commands::Web { port, address, tls_cert, tls_key, tls_hostname } => {
            // Override config TLS settings with CLI arguments if provided
            let mut web_config = app_config.clone();
            if let Some(cert_path) = tls_cert {
                web_config.tls_cert_file = Some(PathBuf::from(cert_path));
            }
            if let Some(key_path) = tls_key {
                web_config.tls_key_file = Some(PathBuf::from(key_path));
            }
            if let Some(hostname) = tls_hostname {
                web_config.tls_hostname = Some(hostname);
            }

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Quitting...");
                }
                res = web_server_command(&web_config, &address, port) => {
                    res.map_err(|err| Box::new(std::io::Error::other(err.to_string())))?;
                }
            }
        }
        Commands::Identify {
            hostname,
            username,
            keyfile,
            key_passphrase,
            ip_address,
            cached,
        } => {
            identify_command(
                &mut app_config,
                config_path,
                hostname,
                username,
                keyfile,
                key_passphrase,
                ip_address,
                cached,
            )
            .await?;
        }
        Commands::Update {
            devices,
            username,
            keyfile,
            key_passphrase,
            cached,
        } => {
            update_command(
                &mut app_config,
                config_path,
                devices,
                username,
                keyfile,
                key_passphrase,
                cached,
            )
            .await?;
        }
        Commands::Pathfind {
            source_ip,
            destination_ip,
            source_device,
            source_interface,
            source_vlan,
            dest_device,
            dest_interface,
            dest_vlan,
        } => {
            pathfind_command(
                &app_config,
                PathEndpoint {
                    device: None,
                    device_id: source_device,
                    interface: source_interface,
                    ip: Some(source_ip),
                    vlan: source_vlan,
                },
                PathEndpoint {
                    device: None,
                    device_id: dest_device,
                    interface: dest_interface,
                    ip: Some(destination_ip),
                    vlan: dest_vlan,
                },
            )
            .await?;
        }
        Commands::ConfigDump { pretty } => {
            config_dump_command(&app_config, pretty)?;
        }
        Commands::Remove {
            hostname,
            delete_state,
        } => {
            remove_command(&mut app_config, config_path, &hostname, delete_state)?;
        }
        Commands::Scan {
            targets,
            port,
            username,
            keyfile,
            key_passphrase,
            timeout,
            add,
            cached,
        } => {
            let scan_options = ScanOptions {
                targets,
                port,
                username,
                keyfile,
                key_passphrase,
                timeout,
                add_devices: add,
                cached,
            };
            scan_command(&mut app_config, config_path, scan_options).await?;
        }
    }

    Ok(())
}

async fn identify_command(
    app_config: &mut AppConfig,
    config_path: &PathBuf,
    target_hostname: Option<String>,
    username: Option<String>,
    keyfile: Option<String>,
    key_passphrase: Option<String>,
    ip_address: Option<String>,
    cached: bool,
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
    let mut successfully_identified_devices = Vec::new();

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
                match app_config.get_device(&hostname) {
                    Some(device) => device.clone(),
                    None => {
                        error!("Device '{}' not found in configuration, skipping", hostname);
                        continue;
                    }
                }
            }
        } else {
            match app_config.get_device(&hostname) {
                Some(device) => device.clone(),
                None => {
                    error!("Device '{}' not found in configuration, skipping", hostname);
                    continue;
                }
            }
        };

        // Apply CLI-provided SSH parameters for runtime use (no prompting yet)
        apply_ssh_params_no_prompts(&mut device_config, &username, &keyfile, &key_passphrase);
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

        match identify_and_interrogate_device(device_config.clone(), cached).await {
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

                // Track successful identification
                successfully_identified_devices.push(hostname.clone());
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
        match crate::neighbor_resolution::resolve_all_neighbor_relationships(&mut device_states_vec)
        {
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

    // Prompt to save CLI SSH parameters to device configs (only for existing devices, only if not cached mode)
    if !cached && !successfully_identified_devices.is_empty() {
        for hostname in &successfully_identified_devices {
            // Only prompt for existing devices, not newly added ones
            if new_device_hostname.as_ref() != Some(hostname) {
                match prompt_to_save_ssh_params(
                    app_config,
                    hostname,
                    &username,
                    &keyfile,
                    &key_passphrase,
                ) {
                    Ok(saved) => {
                        if saved {
                            info!("✅ SSH configuration saved for device '{}'", hostname);
                        }
                    }
                    Err(e) => warn!("Failed to save SSH parameters for '{}': {}", hostname, e),
                }
            }
        }
    }

    // Save updated configuration
    app_config.save_to_file(config_path)?;
    info!("Updated configuration saved to {}", config_path.display());

    Ok(())
}

async fn update_command(
    app_config: &mut AppConfig,
    config_path: &PathBuf,
    specific_devices: Vec<String>,
    username: Option<String>,
    keyfile: Option<String>,
    key_passphrase: Option<String>,
    cached: bool,
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
    let mut successfully_updated_devices = Vec::new();

    let mut tasks = JoinSet::new();

    for hostname in devices_to_update {
        info!("Updating device: {}", hostname);
        if let Some(mut device_config) = app_config.get_device(&hostname).cloned() {
            // Apply CLI-provided SSH parameters for runtime use (no prompting yet)
            apply_ssh_params_no_prompts(&mut device_config, &username, &keyfile, &key_passphrase);

            tasks.spawn(identify_and_interrogate_device(device_config, cached));
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
                    Ok(()) => {
                        info!("Device state updated successfully for {hostname}");
                        successfully_updated_devices.push(hostname);
                    }
                    Err(e) => warn!("Failed to save updated device state for {hostname}: {e}"),
                }
            }
            Ok(Err(e)) => {
                error!("Error during device update: {}", e);
            }
            Err(e) => {
                error!("Failed to update {}", e);
            }
        }
    }

    // Resolve all neighbor relationships after device updates
    let device_states = app_config
        .load_all_device_states()
        .map_err(|e| TrailFinderError::Generic(e.to_string()))?;
    if !device_states.is_empty() {
        let mut device_states_vec = device_states.into_values().collect::<Vec<_>>();
        match crate::neighbor_resolution::resolve_all_neighbor_relationships(&mut device_states_vec)
        {
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

    // Prompt to save CLI SSH parameters to device configs (only if not cached mode)
    if !cached && !successfully_updated_devices.is_empty() {
        for hostname in &successfully_updated_devices {
            match prompt_to_save_ssh_params(
                app_config,
                hostname,
                &username,
                &keyfile,
                &key_passphrase,
            ) {
                Ok(saved) => {
                    if saved {
                        info!("✅ SSH configuration saved for device '{}'", hostname);
                    }
                }
                Err(e) => warn!("Failed to save SSH parameters for '{}': {}", hostname, e),
            }
        }
    }

    // Save updated configuration
    app_config.save_to_file(config_path)?;
    info!("Updated configuration saved to {}", config_path.display());

    Ok(())
}

#[derive(Debug)]
struct AddDeviceParams<'a> {
    hostname: &'a str,
    ip_address: &'a Option<String>,
    username: &'a Option<String>,
    keyfile: &'a Option<String>,
    key_passphrase: &'a Option<String>,
    port: u16,
    owner: &'a Option<String>,
    notes: &'a Option<String>,
    identify: bool,
}

async fn add_command(
    app_config: &mut AppConfig,
    config_path: &PathBuf,
    params: &AddDeviceParams<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check if device already exists
    if app_config.get_device(params.hostname).is_some() {
        return Err(format!(
            "Device '{}' already exists in configuration",
            params.hostname
        )
        .into());
    }

    // Parse IP address if provided
    let parsed_ip = if let Some(ip_str) = params.ip_address {
        Some(
            ip_str
                .parse::<IpAddr>()
                .map_err(|e| format!("Invalid IP address '{}': {}", ip_str, e))?,
        )
    } else {
        None
    };

    // Parse SSH port
    let ssh_port = std::num::NonZeroU16::new(params.port)
        .ok_or_else(|| format!("Invalid SSH port '{}': port must be non-zero", params.port))?;

    // Parse owner
    let device_owner = match params.owner.as_deref() {
        Some(owner_str) => Owner::Named(owner_str.to_string()),
        None => Owner::Unknown,
    };

    // Create device configuration
    let device_config = DeviceConfig {
        device_id: Uuid::new_v4(),
        hostname: params.hostname.to_string(),
        ip_address: parsed_ip,
        brand: None,       // Will be set during identification
        device_type: None, // Will be set during identification
        owner: device_owner,
        ssh_username: params.username.clone(),
        ssh_port,
        ssh_identity_files: if let Some(keyfile_path) = params.keyfile {
            vec![PathBuf::from(keyfile_path)]
        } else {
            Vec::new()
        },
        ssh_key_passphrase: params.key_passphrase.clone(),
        last_interrogated: None,
        notes: params.notes.clone(),
        all_ssh_identity_files: Vec::new(),
        ssh_config: None,
    };

    info!("Adding device '{}' to configuration", params.hostname);

    // Add device to configuration
    app_config.add_device(device_config.clone());

    // Re-process SSH configurations to include the new device
    app_config.process_device_ssh_configs()?;

    // Save updated configuration
    app_config.save_to_file(config_path)?;

    info!(
        "✅ Device '{}' added successfully to configuration",
        params.hostname
    );
    if let Some(ip_addr) = params.ip_address {
        info!("   IP address: {}", ip_addr);
    }
    if let Some(user) = params.username {
        info!("   SSH username: {}", user);
    }
    info!("   SSH port: {}", params.port);
    if let Some(owner_name) = params.owner {
        info!("   Owner: {}", owner_name);
    }
    if let Some(device_notes) = params.notes {
        info!("   Notes: {}", device_notes);
    }

    if params.identify {
        info!("🔍 Automatically identifying device...");
        match identify_and_interrogate_device(device_config.clone(), false).await {
            Ok((device_id, brand, device_type, device_state)) => {
                info!("{device_id} Identified as {:?} {:?}", brand, device_type);
                app_config.update_device_identification(params.hostname, brand, device_type)?;

                // Save device state
                match app_config.save_device_state(params.hostname, &device_state) {
                    Ok(()) => info!(
                        "Device {hostname} state saved successfully",
                        hostname = params.hostname
                    ),
                    Err(e) => warn!(
                        "Failed to save device {hostname} state: {}",
                        e,
                        hostname = params.hostname
                    ),
                }

                // Save updated configuration
                app_config.save_to_file(config_path)?;
                info!(
                    "✅ Device '{}' added and identified successfully",
                    params.hostname
                );
            }
            Err(e) => {
                warn!("Failed to identify device '{}': {}", params.hostname, e);
                info!("Device added to configuration but identification failed");
                info!(
                    "💡 Use 'identify {}' to retry device identification",
                    params.hostname
                );
            }
        }
    } else {
        info!(
            "💡 Use 'identify {}' to automatically detect device type and brand",
            params.hostname
        );
    }

    Ok(())
}

async fn identify_and_interrogate_device(
    device_config: DeviceConfig,
    cached: bool,
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

    // Use the regular SSH connection method - caching is now handled internally
    let mut ssh_client = if cached {
        // For cached mode, create a cache-only client
        SshClient::new_cache_only(&device_config.hostname)
            .map_err(|err| TrailFinderError::Generic(err.to_string()))?
    } else {
        // For normal mode, connect with SSH and enable automatic caching
        SshClient::connect_with_device_config(&device_config, socket_addr, timeout)
            .await
            .map_err(|err| TrailFinderError::Generic(err.to_string()))?
    };

    let (brand, device_type) = DeviceIdentifier::identify_device(&mut ssh_client).await?;

    info!(
        "Interrogating device {} configuration... for brand {brand}",
        device_config.hostname
    );

    // Interrogate device using trait-based approach
    let device_state =
        interrogate_device_by_brand(&brand, &mut ssh_client, &device_config, device_type).await?;

    Ok((device_config.device_id, brand, device_type, device_state))
}

async fn pathfind_command(
    app_config: &AppConfig,
    source: PathEndpoint,
    destination: PathEndpoint,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "🛣️  Finding path from {:?} to {:?}",
        source.ip, destination.ip
    );

    let request = PathFindRequest {
        source,
        destination,
    };

    // Perform pathfinding
    match find_path(app_config, request).await {
        Ok(result) => {
            if result.success {
                print_path_result(&result);
            } else {
                error!(
                    "❌ Pathfinding failed: {}",
                    result.error.unwrap_or_else(|| "Unknown error".to_string())
                );
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("❌ Error during pathfinding: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_path_result(result: &crate::pathfind::PathFindResult) {
    println!("✅ Path found ({} hops):", result.total_hops);
    println!();

    // Calculate column widths based on content
    let hop_width = std::cmp::max(3, result.total_hops.to_string().len());
    let device_width = std::cmp::max(
        6,
        result
            .path
            .iter()
            .map(|h| h.device.len())
            .max()
            .unwrap_or(0),
    );
    let incoming_width = std::cmp::max(
        8,
        result
            .path
            .iter()
            .map(|h| h.incoming_interface.as_ref().map_or(1, |i| i.len()))
            .max()
            .unwrap_or(1),
    );
    let in_vlan_width = std::cmp::max(
        7,
        result
            .path
            .iter()
            .map(|h| h.incoming_vlan.map_or(1, |v| v.to_string().len()))
            .max()
            .unwrap_or(1),
    );
    let outgoing_width = std::cmp::max(
        8,
        result
            .path
            .iter()
            .map(|h| h.outgoing_interface.len())
            .max()
            .unwrap_or(0),
    );
    let out_vlan_width = std::cmp::max(
        8,
        result
            .path
            .iter()
            .map(|h| h.outgoing_vlan.map_or(1, |v| v.to_string().len()))
            .max()
            .unwrap_or(1),
    );
    let gateway_width = std::cmp::max(
        7,
        result
            .path
            .iter()
            .map(|h| h.gateway.as_ref().map_or(1, |g| g.len()))
            .max()
            .unwrap_or(1),
    );
    let network_width = std::cmp::max(
        7,
        result
            .path
            .iter()
            .map(|h| h.network.len())
            .max()
            .unwrap_or(0),
    );

    // Print header
    println!(
        "{:<width_hop$}  {:<width_device$}  {:<width_incoming$}  {:<width_in_vlan$}  {:<width_outgoing$}  {:<width_out_vlan$}  {:<width_gateway$}  {:<width_network$}",
        "Hop",
        "Device",
        "Incoming",
        "In-VLAN",
        "Outgoing",
        "Out-VLAN",
        "Gateway",
        "Network",
        width_hop = hop_width,
        width_device = device_width,
        width_incoming = incoming_width,
        width_in_vlan = in_vlan_width,
        width_outgoing = outgoing_width,
        width_out_vlan = out_vlan_width,
        width_gateway = gateway_width,
        width_network = network_width
    );

    // Calculate total width for separator line
    let total_width = hop_width
        + device_width
        + incoming_width
        + in_vlan_width
        + outgoing_width
        + out_vlan_width
        + gateway_width
        + network_width
        + 14; // +14 for double spaces
    println!("{}", "─".repeat(total_width));

    // Print each hop
    for (i, hop) in result.path.iter().enumerate() {
        let hop_num = format!("{}", i);
        let incoming_str = hop.incoming_interface.as_deref().unwrap_or("-");
        let in_vlan_str = hop
            .incoming_vlan
            .map_or_else(|| "-".to_string(), |v| v.to_string());
        let out_vlan_str = hop
            .outgoing_vlan
            .map_or_else(|| "-".to_string(), |v| v.to_string());
        let gateway_str = hop.gateway.as_deref().unwrap_or("-");

        println!(
            "{:<width_hop$}  {:<width_device$}  {:<width_incoming$}  {:<width_in_vlan$}  {:<width_outgoing$}  {:<width_out_vlan$}  {:<width_gateway$}  {:<width_network$}",
            hop_num,
            hop.device,
            incoming_str,
            in_vlan_str,
            hop.outgoing_interface,
            out_vlan_str,
            gateway_str,
            hop.network,
            width_hop = hop_width,
            width_device = device_width,
            width_incoming = incoming_width,
            width_in_vlan = in_vlan_width,
            width_outgoing = outgoing_width,
            width_out_vlan = out_vlan_width,
            width_gateway = gateway_width,
            width_network = network_width
        );
    }

    println!();
    info!("🎯 Path discovery completed successfully");
}

fn config_dump_command(
    app_config: &AppConfig,
    pretty: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = if pretty {
        serde_json::to_string_pretty(app_config)?
    } else {
        serde_json::to_string(app_config)?
    };
    println!("{}", output);
    Ok(())
}

fn remove_command(
    app_config: &mut AppConfig,
    config_path: &PathBuf,
    hostname: &str,
    delete_state: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Removing device: {}", hostname);

    let device_removed = app_config.remove_device_with_state(hostname, delete_state)?;

    if device_removed {
        if delete_state {
            info!(
                "Device '{}' and its state file removed from configuration",
                hostname
            );
        } else {
            info!(
                "Device '{}' removed from configuration (state file preserved)",
                hostname
            );
        }

        // Save updated configuration
        app_config.save_to_file(config_path)?;
        info!("Configuration saved to {}", config_path.display());
    } else {
        warn!("Device '{}' not found in configuration", hostname);
        return Err(format!("Device '{}' not found", hostname).into());
    }

    Ok(())
}

#[derive(Debug)]
struct ScanOptions {
    targets: Vec<String>,
    port: u16,
    username: Option<String>,
    keyfile: Option<String>,
    key_passphrase: Option<String>,
    timeout: u64,
    add_devices: bool,
    cached: bool,
}

async fn scan_command(
    app_config: &mut AppConfig,
    config_path: &PathBuf,
    options: ScanOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    if options.cached {
        warn!("--cached flag is not yet implemented for scan command, ignoring");
    }

    info!("Starting network scan of {} targets", options.targets.len());

    // TODO: Add key_passphrase support to ScanConfig
    let _key_passphrase = &options.key_passphrase; // Suppress unused field warning

    let scan_config = ScanConfig {
        port: options.port,
        timeout_seconds: options.timeout,
        username: options.username.clone(),
        keyfile: options.keyfile.clone(),
    };

    let discovered_devices =
        network_discovery::scan_network_targets(options.targets, scan_config).await?;

    // Display results
    println!("\n📡 Network Scan Results");
    println!("=======================");

    let mut responsive_count = 0;
    let mut identified_count = 0;
    let mut added_count = 0;

    for device in &discovered_devices {
        if device.ssh_responsive {
            responsive_count += 1;

            println!("\n🌐 Device: {}", device.ip_address);

            if device.identification_successful {
                identified_count += 1;
                println!(
                    "  ✅ Brand: {:?}",
                    device.brand.as_ref().unwrap_or(&DeviceBrand::Unknown)
                );
                println!(
                    "  ✅ Type: {:?}",
                    device.device_type.as_ref().unwrap_or(&DeviceType::Router)
                );
                if let Some(hostname) = &device.hostname {
                    println!("  📝 Hostname: {}", hostname);
                }
            } else {
                println!("  ⚠️  SSH responsive but identification failed");
            }

            // Add to configuration if requested and identification was successful
            if options.add_devices && device.identification_successful {
                let device_config = network_discovery::discovered_device_to_config(
                    device,
                    options.username.clone(),
                    options.keyfile.as_ref(),
                );

                // Check if device already exists
                if app_config.get_device(&device_config.hostname).is_none() {
                    app_config.add_device(device_config);
                    added_count += 1;
                    println!("  ➕ Added to configuration");
                } else {
                    println!("  ⚠️  Already exists in configuration");
                }
            }
        }
    }

    println!("\n📊 Scan Summary:");
    println!("  Total targets scanned: {}", discovered_devices.len());
    println!("  SSH responsive: {}", responsive_count);
    println!("  Successfully identified: {}", identified_count);

    if options.add_devices {
        println!("  Added to configuration: {}", added_count);

        if added_count > 0 {
            app_config.save_to_file(config_path)?;
            info!("Configuration saved to {}", config_path.display());
        }
    } else if identified_count > 0 {
        println!("\n💡 Use --add flag to automatically add discovered devices to configuration");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::{io::Write, str::FromStr};
    use tempfile::NamedTempFile;

    // Helper function to create a temporary config file
    fn create_temp_config_file(content: &str) -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        writeln!(temp_file, "{}", content).expect("Failed to write to temp file");
        temp_file
    }

    // Helper function to create a basic test config
    fn basic_test_config() -> String {
        r#"{
            "devices": [
                {
                    "device_id": "550e8400-e29b-41d4-a716-446655440000",
                    "hostname": "test-router",
                    "owner": {
                        "Named": "Test Lab"
                    },
                    "ssh_username": "admin",
                    "ssh_port": 22,
                    "brand": "Mikrotik",
                    "device_type": "Router"
                }
            ],
            "ssh_timeout_seconds": 30,
            "use_ssh_agent": true,
            "state_directory": "test_states"
        }"#
        .to_string()
    }

    #[test]
    fn test_cli_parsing_basic_commands() {
        // Test web command
        let args = vec![
            "trailfinder",
            "web",
            "--port",
            "8080",
            "--address",
            "0.0.0.0",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::Web { port, address, .. } => {
                assert_eq!(port, 8080);
                assert_eq!(address, "0.0.0.0");
            }
            _ => panic!("Expected Web command"),
        }
    }

    #[test]
    fn test_cli_parsing_identify_command() {
        // Test identify command with all options
        let args = vec![
            "trailfinder",
            "identify",
            "router1",
            "--username",
            "admin",
            "--keyfile",
            "/path/to/key",
            "--ip-address",
            "192.168.1.1",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::Identify {
                hostname,
                username,
                keyfile,
                key_passphrase,
                ip_address,
                cached,
            } => {
                assert_eq!(hostname, Some("router1".to_string()));
                assert_eq!(username, Some("admin".to_string()));
                assert_eq!(keyfile, Some("/path/to/key".to_string()));
                assert_eq!(key_passphrase, None);
                assert_eq!(ip_address, Some("192.168.1.1".to_string()));
                assert!(!cached); // Default should be false
            }
            _ => panic!("Expected Identify command"),
        }
    }

    #[test]
    fn test_cli_parsing_update_command() {
        // Test update command with specific devices
        // Temporarily remove USER env var to test default behavior
        let original_user = std::env::var("USER").ok();
        unsafe {
            std::env::remove_var("USER");
        }

        let args = vec!["trailfinder", "update", "router1", "switch1"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::Update {
                devices,
                username,
                keyfile,
                key_passphrase,
                cached,
            } => {
                assert_eq!(devices, vec!["router1", "switch1"]);
                assert_eq!(username, None);
                assert_eq!(keyfile, None);
                assert_eq!(key_passphrase, None);
                assert!(!cached); // Default should be false
            }
            _ => panic!("Expected Update command"),
        }

        // Restore original USER env var if it existed
        if let Some(user) = original_user {
            unsafe {
                std::env::set_var("USER", user);
            }
        }

        // Test update command with SSH parameters
        // Temporarily remove USER env var to test CLI args take precedence
        let original_user2 = std::env::var("USER").ok();
        unsafe {
            std::env::remove_var("USER");
        }

        let args = vec![
            "trailfinder",
            "update",
            "router1",
            "--username",
            "admin",
            "--keyfile",
            "/path/to/key",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::Update {
                devices,
                username,
                keyfile,
                key_passphrase,
                cached,
            } => {
                assert_eq!(devices, vec!["router1"]);
                assert_eq!(username, Some("admin".to_string()));
                assert_eq!(keyfile, Some("/path/to/key".to_string()));
                assert_eq!(key_passphrase, None);
                assert!(!cached); // Default should be false
            }
            _ => panic!("Expected Update command"),
        }

        // Restore original USER env var if it existed
        if let Some(user) = original_user2 {
            unsafe {
                std::env::set_var("USER", user);
            }
        }
    }

    #[test]
    fn test_cli_parsing_pathfind_command() {
        // Test pathfind command with all options
        let args = vec![
            "trailfinder",
            "pathfind",
            "192.168.1.10",
            "10.0.0.5",
            "--source-device",
            "router1",
            "--source-interface",
            "eth0",
            "--source-vlan",
            "100",
            "--dest-device",
            "router2",
            "--dest-interface",
            "eth1",
            "--dest-vlan",
            "200",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::Pathfind {
                source_ip,
                destination_ip,
                source_device,
                source_interface,
                source_vlan,
                dest_device,
                dest_interface,
                dest_vlan,
            } => {
                assert_eq!(source_ip, "192.168.1.10");
                assert_eq!(destination_ip, "10.0.0.5");
                assert_eq!(source_device, Some("router1".to_string()));
                assert_eq!(source_interface, Some("eth0".to_string()));
                assert_eq!(source_vlan, Some(100));
                assert_eq!(dest_device, Some("router2".to_string()));
                assert_eq!(dest_interface, Some("eth1".to_string()));
                assert_eq!(dest_vlan, Some(200));
            }
            _ => panic!("Expected Pathfind command"),
        }
    }

    #[test]
    fn test_cli_parsing_global_options() {
        // Test global options
        let args = vec!["trailfinder", "--debug", "--config", "custom.json", "web"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        assert!(cli.debug);
        assert_eq!(
            cli.config_path,
            PathBuf::from_str("custom.json").expect("Failed to parse")
        );
    }

    #[test]
    fn test_cli_parsing_default_command() {
        // Test that identify is the default command when no command is specified
        let args = vec!["trailfinder"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_err());
    }

    #[test]
    fn test_path_endpoint_creation_from_cli() {
        // Test PathEndpoint creation from CLI arguments (as done in pathfind command)
        let source = PathEndpoint {
            device: None,
            device_id: Some("router1".to_string()),
            interface: Some("eth0".to_string()),
            ip: Some("192.168.1.10".to_string()),
            vlan: Some(100),
        };

        assert_eq!(source.device_id, Some("router1".to_string()));
        assert_eq!(source.interface, Some("eth0".to_string()));
        assert_eq!(source.ip, Some("192.168.1.10".to_string()));
        assert_eq!(source.vlan, Some(100));
    }

    #[tokio::test]
    async fn test_config_file_loading_existing() {
        let config_content = basic_test_config();
        let temp_file = create_temp_config_file(&config_content);
        let config_path = temp_file.path().to_str().unwrap();

        // Test loading existing config
        let result = AppConfig::load_from_file(config_path);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.devices.len(), 1);
        assert_eq!(config.devices[0].hostname, "test-router");
    }

    #[tokio::test]
    async fn test_config_file_creation_nonexistent() {
        // Test config creation when file doesn't exist
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let config_path = temp_file.path().to_str().unwrap();

        // Remove the file so it doesn't exist
        std::fs::remove_file(config_path).expect("Failed to remove temp file");

        // This should create a default config
        let result = AppConfig::load_from_file(config_path);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.devices.len(), 0); // Default config has no devices

        // File should now exist
        assert!(std::path::Path::new(config_path).exists());
    }

    #[tokio::test]
    async fn test_config_file_loading_invalid_json() {
        let invalid_json = "{ invalid json content";
        let temp_file = create_temp_config_file(invalid_json);
        let config_path = temp_file.path().to_str().unwrap();

        // This should return an error for invalid JSON
        let result = AppConfig::load_from_file(config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_print_path_result_formatting() {
        // Test the path result printing function
        use crate::pathfind::{PathFindResult, PathHop};

        let hops = vec![
            PathHop {
                device: "Source: 192.168.1.10".to_string(),
                incoming_interface: None,
                incoming_vlan: None,
                outgoing_interface: "-".to_string(),
                outgoing_vlan: None,
                gateway: None,
                network: "-".to_string(),
                source_ip: Some("192.168.1.10".to_string()),
            },
            PathHop {
                device: "router1".to_string(),
                incoming_interface: Some("eth0".to_string()),
                incoming_vlan: Some(100),
                outgoing_interface: "eth1".to_string(),
                outgoing_vlan: Some(200),
                gateway: Some("192.168.1.1".to_string()),
                network: "0.0.0.0/0".to_string(),
                source_ip: None,
            },
        ];

        let result = PathFindResult {
            path: hops,
            total_hops: 2,
            success: true,
            error: None,
        };

        // This should not panic and should format correctly
        // We can't easily test the output without capturing stdout,
        // but we can at least verify the function doesn't crash
        print_path_result(&result);
    }

    #[test]
    fn test_calculate_column_widths() {
        use crate::pathfind::PathHop;

        let hops = [PathHop {
            device: "Very Long Device Name That Should Affect Width".to_string(),
            incoming_interface: Some("GigabitEthernet0/0/1".to_string()),
            incoming_vlan: Some(1234),
            outgoing_interface: "TenGigabitEthernet1/1/1".to_string(),
            outgoing_vlan: Some(4094),
            gateway: Some("192.168.100.254".to_string()),
            network: "172.16.255.0/24".to_string(),
            source_ip: None,
        }];

        // Test that width calculation handles long strings correctly
        let device_width = hops
            .iter()
            .map(|hop| hop.device.len())
            .max()
            .unwrap_or(6)
            .max(6);

        assert!(device_width >= "Very Long Device Name That Should Affect Width".len());

        let incoming_width = hops
            .iter()
            .map(|hop| hop.incoming_interface.as_deref().unwrap_or("-").len())
            .max()
            .unwrap_or(8)
            .max(8);

        assert!(incoming_width >= "GigabitEthernet0/0/1".len());
    }

    #[test]
    fn test_ip_address_parsing() {
        // Test valid IP addresses
        let valid_ips = vec![
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "::1",
            "2001:db8::1",
        ];

        for ip_str in valid_ips {
            let result = ip_str.parse::<IpAddr>();
            assert!(result.is_ok(), "Failed to parse valid IP: {}", ip_str);
        }

        // Test invalid IP addresses
        let invalid_ips = vec![
            "256.256.256.256",
            "not.an.ip",
            "192.168.1",
            "192.168.1.1.1",
            "",
        ];

        for ip_str in invalid_ips {
            let result = ip_str.parse::<IpAddr>();
            assert!(
                result.is_err(),
                "Should have failed to parse invalid IP: {}",
                ip_str
            );
        }
    }

    #[test]
    fn test_socket_addr_creation() {
        // Test socket address creation from hostname and port
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let port = 22;
        let socket_addr = SocketAddr::new(ip, port);

        assert_eq!(socket_addr.ip(), ip);
        assert_eq!(socket_addr.port(), port);
    }

    // Mock tests for command functions (these test the structure without external dependencies)

    #[tokio::test]
    async fn test_pathfind_command_structure() {
        // Test that pathfind command creates proper PathEndpoint structures
        let source = PathEndpoint {
            device: None,
            device_id: Some("source-device".to_string()),
            interface: Some("eth0".to_string()),
            ip: Some("192.168.1.10".to_string()),
            vlan: Some(100),
        };

        let destination = PathEndpoint {
            device: None,
            device_id: Some("dest-device".to_string()),
            interface: Some("eth1".to_string()),
            ip: Some("10.0.0.1".to_string()),
            vlan: Some(200),
        };

        let request = PathFindRequest {
            source,
            destination,
        };

        // Verify request structure
        assert_eq!(request.source.device_id, Some("source-device".to_string()));
        assert_eq!(
            request.destination.device_id,
            Some("dest-device".to_string())
        );
        assert_eq!(request.source.ip, Some("192.168.1.10".to_string()));
        assert_eq!(request.destination.ip, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_device_config_defaults() {
        let device_config = DeviceConfig {
            hostname: "test-device".to_string(),
            ..DeviceConfig::default()
        };

        assert_eq!(device_config.hostname, "test-device");
        assert!(device_config.ip_address.is_none());
        assert!(device_config.ssh_username.is_none());
        assert_eq!(device_config.ssh_port.get(), 22);
    }

    #[test]
    fn test_cli_help_generation() {
        // Test that help can be generated without panicking
        let _cli = Cli::parse_from(vec!["trailfinder", "--help"]);
        // This test mainly ensures the CLI structure is valid for help generation
        // The actual help text generation is tested by clap internally
    }

    #[test]
    fn test_cli_version_flag() {
        // Test version flag parsing
        let result = Cli::try_parse_from(vec!["trailfinder", "--version"]);
        // Version flag causes early exit, so this would be an "error" in try_parse_from
        // but it's the expected behavior
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parsing_config_dump_command() {
        // Test config-dump command with pretty flag
        let args = vec!["trailfinder", "config-dump", "--pretty"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::ConfigDump { pretty } => {
                assert!(pretty);
            }
            _ => panic!("Expected ConfigDump command"),
        }

        // Test config-dump command without pretty flag
        let args = vec!["trailfinder", "config-dump"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::ConfigDump { pretty } => {
                assert!(!pretty);
            }
            _ => panic!("Expected ConfigDump command"),
        }
    }

    #[test]
    fn test_config_dump_command_execution() {
        let config = AppConfig::default();

        // Test that the function doesn't panic and produces valid JSON
        let result = config_dump_command(&config, false);
        assert!(result.is_ok());

        let result = config_dump_command(&config, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_commands_enum_variants() {
        // Test that all command variants can be constructed
        let add_cmd = Commands::Add {
            hostname: "test-device.example.com".to_string(),
            ip_address: Some("192.168.1.1".to_string()),
            username: Some("admin".to_string()),
            keyfile: Some("/path/to/key".to_string()),
            key_passphrase: None,
            port: 2222,
            owner: Some("Lab Network".to_string()),
            notes: Some("Test device".to_string()),
            identify: false,
        };
        match add_cmd {
            Commands::Add { hostname, port, .. } => {
                assert_eq!(hostname, "test-device.example.com");
                assert_eq!(port, 2222);
            }
            _ => panic!("Unexpected command variant"),
        }

        let web_cmd = Commands::Web {
            port: 8000,
            address: "127.0.0.1".to_string(),
            tls_cert: None,
            tls_key: None,
            tls_hostname: None,
        };
        match web_cmd {
            Commands::Web { port, address, .. } => {
                assert_eq!(port, 8000);
                assert_eq!(address, "127.0.0.1");
            }
            _ => panic!("Unexpected command variant"),
        }

        let identify_cmd = Commands::Identify {
            hostname: Some("router1".to_string()),
            username: None,
            keyfile: None,
            key_passphrase: None,
            ip_address: None,
            cached: false,
        };
        match identify_cmd {
            Commands::Identify { hostname, .. } => {
                assert_eq!(hostname, Some("router1".to_string()));
            }
            _ => panic!("Unexpected command variant"),
        }

        let remove_cmd = Commands::Remove {
            hostname: "test-device".to_string(),
            delete_state: true,
        };
        match remove_cmd {
            Commands::Remove {
                hostname,
                delete_state,
            } => {
                assert_eq!(hostname, "test-device");
                assert!(delete_state);
            }
            _ => panic!("Unexpected command variant"),
        }

        let scan_cmd = Commands::Scan {
            targets: vec!["192.168.1.0/24".to_string()],
            port: 22,
            username: Some("admin".to_string()),
            keyfile: None,
            key_passphrase: None,
            timeout: 5,
            add: false,
            cached: false,
        };
        match scan_cmd {
            Commands::Scan {
                targets,
                port,
                username,
                timeout,
                add,
                ..
            } => {
                assert_eq!(targets, vec!["192.168.1.0/24"]);
                assert_eq!(port, 22);
                assert_eq!(username, Some("admin".to_string()));
                assert_eq!(timeout, 5);
                assert!(!add);
            }
            _ => panic!("Unexpected command variant"),
        }
    }

    #[test]
    fn test_cli_parsing_remove_command() {
        // Test remove command parsing
        let args = vec!["trailfinder", "remove", "test-device"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::Remove {
                hostname,
                delete_state,
            } => {
                assert_eq!(hostname, "test-device");
                assert!(!delete_state); // Default should be false
            }
            _ => panic!("Expected Remove command"),
        }

        // Test with delete-state flag
        let args = vec!["trailfinder", "remove", "test-device", "--delete-state"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::Remove {
                hostname,
                delete_state,
            } => {
                assert_eq!(hostname, "test-device");
                assert!(delete_state);
            }
            _ => panic!("Expected Remove command"),
        }
    }

    #[test]
    fn test_cli_parsing_add_command() {
        // Test basic add command
        // Temporarily remove USER env var to test default behavior
        let original_user = std::env::var("USER").ok();
        unsafe {
            std::env::remove_var("USER");
        }

        let args = vec!["trailfinder", "add", "test-device.example.com"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::Add {
                hostname,
                ip_address,
                username,
                keyfile,
                key_passphrase,
                port,
                owner,
                notes,
                identify,
            } => {
                assert_eq!(hostname, "test-device.example.com");
                assert_eq!(ip_address, None);
                assert_eq!(username, None);
                assert_eq!(keyfile, None);
                assert_eq!(key_passphrase, None);
                assert_eq!(port, 22); // Default
                assert_eq!(owner, None);
                assert_eq!(notes, None);
                assert!(!identify); // Default
            }
            _ => panic!("Expected Add command"),
        }

        // Restore original USER env var if it existed
        if let Some(user) = original_user {
            unsafe {
                std::env::set_var("USER", user);
            }
        }

        // Test add command with all options
        // Temporarily remove USER env var to test CLI args take precedence
        let original_user2 = std::env::var("USER").ok();
        unsafe {
            std::env::remove_var("USER");
        }

        let args = vec![
            "trailfinder",
            "add",
            "router1.example.com",
            "--ip-address",
            "192.168.1.1",
            "--username",
            "admin",
            "--keyfile",
            "/path/to/key",
            "--port",
            "2222",
            "--owner",
            "Lab Network",
            "--notes",
            "Primary router",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::Add {
                hostname,
                ip_address,
                username,
                keyfile,
                key_passphrase,
                port,
                owner,
                notes,
                identify,
            } => {
                assert_eq!(hostname, "router1.example.com");
                assert_eq!(ip_address, Some("192.168.1.1".to_string()));
                assert_eq!(username, Some("admin".to_string()));
                assert_eq!(keyfile, Some("/path/to/key".to_string()));
                assert_eq!(key_passphrase, None);
                assert_eq!(port, 2222);
                assert_eq!(owner, Some("Lab Network".to_string()));
                assert_eq!(notes, Some("Primary router".to_string()));
                assert!(!identify);
            }
            _ => panic!("Expected Add command"),
        }

        // Restore original USER env var if it existed
        if let Some(user) = original_user2 {
            unsafe {
                std::env::set_var("USER", user);
            }
        }
    }

    #[test]
    fn test_cli_parsing_scan_command() {
        // Test basic scan command
        let args = vec!["trailfinder", "scan", "192.168.1.1", "10.0.0.0/24"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::Scan {
                targets,
                port,
                timeout,
                add,
                ..
            } => {
                assert_eq!(targets, vec!["192.168.1.1", "10.0.0.0/24"]);
                assert_eq!(port, 22); // Default
                assert_eq!(timeout, 5); // Default
                assert!(!add); // Default
            }
            _ => panic!("Expected Scan command"),
        }

        // Test with all options
        let args = vec![
            "trailfinder",
            "scan",
            "192.168.1.0/24",
            "-p",
            "2222",
            "-u",
            "admin",
            "-k",
            "/path/to/key",
            "-t",
            "10",
            "--add",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        match cli.command {
            Commands::Scan {
                targets,
                port,
                username,
                keyfile,
                key_passphrase: _,
                timeout,
                add,
                cached,
            } => {
                assert_eq!(targets, vec!["192.168.1.0/24"]);
                assert_eq!(port, 2222);
                assert_eq!(username, Some("admin".to_string()));
                assert_eq!(keyfile, Some("/path/to/key".to_string()));
                assert_eq!(timeout, 10);
                assert!(add);
                assert!(!cached); // Default should be false
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[tokio::test]
    async fn test_add_command_functionality() {
        use crate::config::AppConfig;
        use tempfile::NamedTempFile;

        // Create a temporary config file
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let config_path = temp_file.path().to_path_buf();

        // Create empty config
        let mut app_config = AppConfig::default();

        // Test adding a device with minimal options
        let params = AddDeviceParams {
            hostname: "test-device.example.com",
            ip_address: &None,
            username: &None,
            keyfile: &None,
            key_passphrase: &None,
            port: 22,
            owner: &None,
            notes: &None,
            identify: false,
        };
        let result = add_command(&mut app_config, &config_path, &params);
        assert!(result.await.is_ok());
        assert_eq!(app_config.devices.len(), 1);
        assert_eq!(app_config.devices[0].hostname, "test-device.example.com");
        assert_eq!(app_config.devices[0].ssh_port.get(), 22);
        assert!(app_config.devices[0].ip_address.is_none());

        // Test adding a device with all options
        let ip = Some("192.168.1.1".to_string());
        let user = Some("admin".to_string());
        let key = Some("/path/to/key".to_string());
        let owner_val = Some("Lab Network".to_string());
        let notes_val = Some("Primary router".to_string());
        let key_passphrase = None;
        let params = AddDeviceParams {
            hostname: "router1.example.com",
            ip_address: &ip,
            username: &user,
            keyfile: &key,
            key_passphrase: &key_passphrase,
            port: 2222,
            owner: &owner_val,
            notes: &notes_val,
            identify: false,
        };
        let result = add_command(&mut app_config, &config_path, &params);
        assert!(result.await.is_ok());
        assert_eq!(app_config.devices.len(), 2);

        let new_device = &app_config.devices[1];
        assert_eq!(new_device.hostname, "router1.example.com");
        assert_eq!(new_device.ip_address, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(new_device.ssh_username, Some("admin".to_string()));
        assert_eq!(new_device.ssh_port.get(), 2222);
        assert_eq!(new_device.notes, Some("Primary router".to_string()));

        // Test adding duplicate device (should fail)
        let params = AddDeviceParams {
            hostname: "test-device.example.com",
            ip_address: &None,
            username: &None,
            keyfile: &None,
            key_passphrase: &None,
            port: 22,
            owner: &None,
            notes: &None,
            identify: false,
        };
        let result = add_command(&mut app_config, &config_path, &params);
        assert!(result.await.is_err());
        assert_eq!(app_config.devices.len(), 2); // No change
    }

    #[tokio::test]
    async fn test_add_command_invalid_ip() {
        use crate::config::AppConfig;
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let config_path = temp_file.path().to_path_buf();
        let mut app_config = AppConfig::default();

        // Test with invalid IP address
        let invalid_ip = Some("invalid.ip.address".to_string());
        let params = AddDeviceParams {
            hostname: "test-device.example.com",
            ip_address: &invalid_ip,
            username: &None,
            keyfile: &None,
            key_passphrase: &None,
            port: 22,
            owner: &None,
            notes: &None,
            identify: false,
        };
        let result = add_command(&mut app_config, &config_path, &params);
        assert!(result.await.is_err());
        assert_eq!(app_config.devices.len(), 0); // No device added
    }

    #[tokio::test]
    async fn test_add_command_invalid_port() {
        use crate::config::AppConfig;
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let config_path = temp_file.path().to_path_buf();
        let mut app_config = AppConfig::default();

        // Test with port 0 (invalid)
        let params = AddDeviceParams {
            hostname: "test-device.example.com",
            ip_address: &None,
            username: &None,
            keyfile: &None,
            key_passphrase: &None,
            port: 0,
            owner: &None,
            notes: &None,
            identify: false,
        };
        let result = add_command(&mut app_config, &config_path, &params);
        assert!(result.await.is_err());
        assert_eq!(app_config.devices.len(), 0); // No device added
    }

    #[test]
    fn test_error_display_formatting() {
        let error = TrailFinderError::NotFound("Device not found".to_string());
        let error_string = format!("{}", error);
        assert!(error_string.contains("Device not found"));

        let parse_error = TrailFinderError::Parse("Parse failed".to_string());
        let parse_string = format!("{}", parse_error);
        assert!(parse_string.contains("Parse failed"));
    }
}
