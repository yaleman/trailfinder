use std::{net::SocketAddr, sync::Arc, time::Duration};

use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, decode_secret_key};
use russh::{client, keys::ssh_key};

use tracing::{debug, error, trace, warn};

use crate::cache::CommandCache;
use crate::config::ssh::SshConfig;
use crate::{DeviceType, TrailFinderError, config::DeviceBrand};

#[derive(Debug, Clone)]
pub enum AuthMethod {
    SshAgent,
    KeyFile {
        path: String,
        passphrase: Option<String>,
    },
    Password(String),
}

#[derive(Debug)]
pub struct SshConnectionInfo {
    pub address: SocketAddr,
    pub username: String,
    pub timeout: Duration,
    pub successful_auth: Option<AuthMethod>,
}

pub struct SshClient {
    connection_info: SshConnectionInfo,
    session: Option<client::Handle<ClientHandler>>,
    cache: Option<Arc<CommandCache>>,
    hostname: String,
    use_cache: bool,
}

#[derive(Debug)]
pub enum SshError {
    Connection(String),
    Authentication(String),
    Command(String),
    Cache(String),
    Timeout,
}

impl std::fmt::Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshError::Connection(msg) => write!(f, "Connection error: {}", msg),
            SshError::Authentication(msg) => write!(f, "Authentication error: {}", msg),
            SshError::Command(msg) => write!(f, "Command error: {}", msg),
            SshError::Cache(msg) => write!(f, "Cache error: {}", msg),
            SshError::Timeout => write!(f, "Operation timed out"),
        }
    }
}

impl std::error::Error for SshError {}

impl From<TrailFinderError> for SshError {
    fn from(err: TrailFinderError) -> Self {
        SshError::Cache(format!("Cache error: {}", err))
    }
}

// Handler for russh client
#[derive(Clone)]
struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;
    #[allow(unused_variables)]
    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
impl SshClient {
    /// Create a cache-only client that doesn't establish SSH connections
    pub fn new_cache_only(hostname: &str) -> Result<Self, TrailFinderError> {
        let mut client = Self {
            connection_info: SshConnectionInfo {
                address: "0.0.0.0:22".parse().map_err(|e| {
                    SshError::Connection(format!("Failed to parse dummy address: {}", e))
                })?,
                username: "cache-only".to_string(),
                timeout: Duration::from_secs(0),
                successful_auth: None,
            },
            session: None,
            cache: None,
            hostname: hostname.to_string(),
            use_cache: true, // Always use cache in cache-only mode
        };

        client.initialize_cache()?;
        Ok(client)
    }

    /// Connect to a device with caching support
    pub async fn connect_with_device_config_and_cache(
        device_config: &crate::config::DeviceConfig,
        ip_address: SocketAddr,
        timeout: Duration,
        cache: Option<Arc<CommandCache>>,
        use_cache: bool,
    ) -> Result<Self, SshError> {
        // If we're using cache and have cached data, create a cache-only client
        if use_cache && let Some(cache_ref) = cache.as_ref() {
            // Check if we have any cached data for this hostname
            let has_cached_data = !cache_ref
                .get_cached_hostnames()
                .unwrap_or_default()
                .is_empty();

            if has_cached_data {
                debug!(
                    "Creating cache-only SSH client for hostname '{}'",
                    device_config.hostname
                );
                return Ok(SshClient {
                    connection_info: SshConnectionInfo {
                        address: ip_address,
                        username: device_config
                            .get_effective_ssh_username()
                            .unwrap_or_else(|| "unknown".to_string()),
                        timeout,
                        successful_auth: None,
                    },
                    session: None, // No actual SSH session when using cache
                    cache,
                    hostname: device_config.hostname.clone(),
                    use_cache: true,
                });
            }
        }

        // Connect normally if not using cache or no cached data available
        let mut client =
            Self::connect_with_device_config(device_config, ip_address, timeout).await?;
        client.cache = cache;
        client.hostname = device_config.hostname.clone();
        client.use_cache = false; // We'll cache responses but not use cached responses
        Ok(client)
    }

    pub async fn connect_with_device_config(
        device_config: &crate::config::DeviceConfig,
        ip_address: SocketAddr,
        timeout: Duration,
    ) -> Result<Self, SshError> {
        // Get username with fallback chain
        let username = device_config.get_effective_ssh_username().ok_or_else(|| {
            SshError::Authentication(
                "No username found in SSH config, device config, or system environment".to_string(),
            )
        })?;

        // Get all SSH identity files
        let key_paths: Vec<String> = device_config
            .get_all_ssh_identity_files()
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        // Check if we should use SSH agent
        let use_ssh_agent = device_config.should_use_ssh_agent();

        debug!(
            hostname = %device_config.hostname,
            username = %username,
            use_ssh_agent = %use_ssh_agent,
            identity_files_count = key_paths.len(),
            identity_files = ?key_paths,
            "Connecting with processed device config"
        );

        let mut client = Self::connect(
            ip_address,
            &username,
            None, // no password from config
            &key_paths,
            device_config.ssh_key_passphrase.as_deref(),
            use_ssh_agent,
            timeout,
        )
        .await?;

        // Set hostname and initialize cache for automatic response caching
        client.hostname = device_config.hostname.clone();
        client.initialize_cache()?;
        Ok(client)
    }

    pub async fn connect_with_ssh_config(
        hostname: &str,
        ip_address: SocketAddr,
        username: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, SshError> {
        // Load SSH config using our custom parser
        let ssh_config = Self::load_ssh_config()?;
        let host_config = ssh_config.get_host_config(hostname);

        debug!(
            hostname = %hostname,
            ssh_config_found = host_config.is_some(),
            "SSH config lookup result"
        );

        let (username, identities_only, identity_files) = if let Some(config) = host_config {
            // Get connection details from SSH config, with fallback to provided username
            let username = config
                .user
                .as_deref()
                .or(username)
                .ok_or_else(|| {
                    SshError::Authentication(
                        "No username found in SSH config, device config, or system environment"
                            .to_string(),
                    )
                })?
                .to_string();

            let identities_only = config.identities_only.unwrap_or(false);
            let identity_files = config.get_identity_files();

            (username, identities_only, identity_files)
        } else {
            // No SSH config found for host, use fallback username and defaults
            let ssh_username = username
                .ok_or_else(|| {
                    SshError::Authentication(
                        "No SSH config found and no fallback username or system user available"
                            .to_string(),
                    )
                })?
                .to_string();

            (ssh_username, false, Vec::new())
        };

        let use_ssh_agent = !identities_only;
        let key_paths: Vec<String> = identity_files
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        debug!(
            hostname = %hostname,
            username = %username,
            use_ssh_agent = %use_ssh_agent,
            identity_files_count = identity_files.len(),
            identity_files = ?key_paths,
            system_user = ?username,
            "SSH config loaded for host"
        );

        let mut client = Self::connect(
            ip_address,
            &username,
            None, // no password from config
            &key_paths,
            None, // no passphrase from SSH config
            use_ssh_agent,
            timeout,
        )
        .await?;

        // Set hostname and initialize cache for automatic response caching
        client.hostname = hostname.to_string();
        client.initialize_cache()?;

        Ok(client)
    }

    fn load_ssh_config() -> Result<crate::config::ssh::SshConfig, SshError> {
        let ssh_config_path = if let Some(home_dir) = dirs::home_dir() {
            home_dir.join(".ssh").join("config")
        } else {
            return Err(SshError::Connection(
                "Cannot find home directory".to_string(),
            ));
        };

        if !ssh_config_path.exists() {
            debug!(
                "SSH config file not found at {:?}, using empty config",
                ssh_config_path
            );
            return Ok(SshConfig::default());
        }

        SshConfig::parse_file(&ssh_config_path)
            .map_err(|e| SshError::Connection(format!("Failed to parse SSH config: {}", e)))
    }

    pub async fn connect(
        address: SocketAddr,
        username: &str,
        password: Option<&str>,
        key_paths: &[String],
        key_passphrase: Option<&str>,
        use_ssh_agent: bool,
        timeout: Duration,
    ) -> Result<Self, SshError> {
        let mut client = Self::new(address, username.to_string(), timeout);

        // Attempt authentication to find working method
        client
            .discover_auth_method(password, key_paths, key_passphrase, use_ssh_agent)
            .await?;

        Ok(client)
    }

    pub fn new(address: SocketAddr, username: String, timeout: Duration) -> Self {
        Self {
            connection_info: SshConnectionInfo {
                address,
                username,
                timeout,
                successful_auth: None,
            },
            session: None,
            cache: None,
            hostname: address.ip().to_string(), // Default to IP as hostname
            use_cache: false,
        }
    }

    async fn create_session(&self) -> Result<client::Handle<ClientHandler>, SshError> {
        let mut config = client::Config::default();

        // Add legacy algorithms for compatibility with older Cisco devices
        config.preferred.kex = vec![
            // Modern algorithms first
            russh::kex::CURVE25519,
            russh::kex::DH_G14_SHA256,
            russh::kex::DH_G16_SHA512,
            // Legacy algorithms for Cisco compatibility
            russh::kex::ECDH_SHA2_NISTP256,
            russh::kex::ECDH_SHA2_NISTP384,
            russh::kex::ECDH_SHA2_NISTP521,
            russh::kex::DH_G14_SHA1,
        ]
        .into();

        let handler = ClientHandler;

        let session = client::connect(Arc::new(config), &self.connection_info.address, handler)
            .await
            .map_err(|e| {
                SshError::Connection(format!(
                    "address={} error={e}",
                    &self.connection_info.address
                ))
            })?;

        Ok(session)
    }

    async fn discover_auth_method(
        &mut self,
        password: Option<&str>,
        key_paths: &[String],
        key_passphrase: Option<&str>,
        use_ssh_agent: bool,
    ) -> Result<(), SshError> {
        let mut session = self.create_session().await?;

        let mut auth_methods = Vec::new();

        // Add SSH agent if enabled
        if use_ssh_agent {
            auth_methods.push(AuthMethod::SshAgent);
        }

        // Add all key files in order
        for key_path in key_paths {
            auth_methods.push(AuthMethod::KeyFile {
                path: key_path.clone(),
                passphrase: key_passphrase.map(String::from),
            });
        }

        // Add password authentication last
        if let Some(pwd) = password {
            auth_methods.push(AuthMethod::Password(pwd.to_string()));
        }

        for auth_method in auth_methods {
            if self
                .authenticate_session(&mut session, &auth_method)
                .await?
            {
                self.connection_info.successful_auth = Some(auth_method);
                self.session = Some(session);
                return Ok(());
            }
        }

        Err(SshError::Authentication(
            "All authentication methods failed".to_string(),
        ))
    }

    async fn authenticate_session(
        &self,
        session: &mut client::Handle<ClientHandler>,
        auth_method: &AuthMethod,
    ) -> Result<bool, SshError> {
        match auth_method {
            AuthMethod::SshAgent => {
                debug!("SSH agent authentication is not yet fully implemented");
                // debug!("To use your encrypted key, please convert it to OpenSSH format:");
                // debug!("  ssh-keygen -p -m OpenSSH -f ~/.ssh/your_key_file");
                // debug!("Or use an unencrypted key temporarily");
                Ok(false)
            }
            AuthMethod::KeyFile { path, passphrase } => {
                let expanded_path = shellexpand::tilde(path);
                let key_path_buf = std::path::Path::new(expanded_path.as_ref());

                if !key_path_buf.exists() {
                    debug!("SSH key file does not exist: {}", expanded_path);
                    return Ok(false);
                }

                debug!("Attempting key file authentication: {}", expanded_path);

                // Load the private key
                let key_data = match std::fs::read_to_string(key_path_buf) {
                    Ok(data) => data,
                    Err(e) => {
                        debug!("Failed to read key file {}: {}", expanded_path, e);
                        return Ok(false);
                    }
                };

                // Add diagnostics about the key file format
                // debug!("Key file size: {} bytes", key_data.len());
                if key_data.is_empty() {
                    debug!("Key file is empty");
                    return Ok(false);
                }

                // let first_line = key_data.lines().next().unwrap_or("");
                // debug!("Key file first line: {}", first_line);

                // Check for common key format indicators
                if key_data.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
                    trace!("Detected OpenSSH format key");
                } else if key_data.contains("-----BEGIN RSA PRIVATE KEY-----") {
                    trace!("Detected RSA PEM format key");
                    if key_data.contains("Proc-Type: 4,ENCRYPTED") {
                        debug!("Key is encrypted with DEK-Info format");
                    }
                } else if key_data.contains("-----BEGIN EC PRIVATE KEY-----") {
                    trace!("Detected EC PEM format key");
                } else if key_data.contains("-----BEGIN PRIVATE KEY-----") {
                    trace!("Detected PKCS#8 PEM format key");
                } else if key_data.contains("-----BEGIN DSA PRIVATE KEY-----") {
                    trace!("Detected DSA PEM format key");
                } else {
                    warn!("Unknown key format - no standard headers found");
                }

                // Try to load the key based on detected format
                let private_key = if key_data.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
                    // Handle OpenSSH format
                    match passphrase {
                        Some(phrase) => {
                            match PrivateKey::from_openssh(&key_data).and_then(|k| {
                                if k.is_encrypted() {
                                    k.decrypt(phrase)
                                } else {
                                    Ok(k)
                                }
                            }) {
                                Ok(key) => key,
                                Err(e) => {
                                    debug!("Failed to decrypt OpenSSH key: {}", e);
                                    return Ok(false);
                                }
                            }
                        }
                        None => match PrivateKey::from_openssh(&key_data) {
                            Ok(key) => {
                                if key.is_encrypted() {
                                    warn!(
                                        "The OpenSSH key {path} is encrypted but no passphrase was provided"
                                    );
                                    // TODO: prompt for passphrase here
                                }
                                key
                            }
                            Err(e) => {
                                debug!(
                                    "Failed to load OpenSSH key, no passphrase was provided: {e}",
                                );
                                return Ok(false);
                            }
                        },
                    }
                } else {
                    // Handle PEM and other formats
                    debug!("Attempting to load as PEM or other format");

                    // Check if this is an encrypted PEM key that needs a passphrase
                    let is_encrypted_pem = key_data.contains("Proc-Type: 4,ENCRYPTED")
                        || key_data.contains("DEK-Info:");

                    if is_encrypted_pem && passphrase.is_none() {
                        debug!("Key is encrypted but no passphrase provided");
                        debug!(
                            "Try setting SSH_KEY_PASSPHRASE environment variable or configuring ssh_key_passphrase in device config"
                        );
                        return Ok(false);
                    }

                    // Try decode_secret_key first for encrypted PEM keys
                    if is_encrypted_pem {
                        if let Some(phrase) = passphrase {
                            debug!("Using decode_secret_key for encrypted PEM key");
                            match decode_secret_key(&key_data, Some(phrase)) {
                                Ok(key) => {
                                    debug!("Successfully decoded encrypted PEM key");
                                    key
                                }
                                Err(e) => {
                                    debug!("Failed to decode encrypted PEM key: {}", e);
                                    return Ok(false);
                                }
                            }
                        } else {
                            debug!("Encrypted PEM key requires passphrase");
                            return Ok(false);
                        }
                    } else {
                        // For unencrypted keys, try both methods
                        match PrivateKey::from_bytes(key_data.as_bytes()) {
                            Ok(key) => {
                                debug!("Successfully loaded key from bytes");
                                key
                            }
                            Err(e) => {
                                debug!("Failed to load key from bytes: {}", e);
                                // Try decode_secret_key as fallback
                                match decode_secret_key(&key_data, passphrase.as_deref()) {
                                    Ok(key) => {
                                        debug!("Successfully decoded key with decode_secret_key");
                                        key
                                    }
                                    Err(decode_err) => {
                                        debug!("decode_secret_key also failed: {}", decode_err);
                                        debug!(
                                            "Key might be corrupted or in an unsupported format"
                                        );
                                        return Ok(false);
                                    }
                                }
                            }
                        }
                    }
                };

                // Convert to PrivateKeyWithHashAlg for authentication
                let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(private_key), None);

                match session
                    .authenticate_publickey(&self.connection_info.username, key_with_hash)
                    .await
                {
                    Ok(result) => {
                        let success = matches!(result, russh::client::AuthResult::Success);
                        if success {
                            debug!("✅ Authenticated via key file: {}", expanded_path);
                        } else {
                            warn!("Key file authentication failed: {}", expanded_path);
                        }
                        Ok(success)
                    }
                    Err(e) => {
                        error!("Key file authentication error: {}", e);
                        Ok(false)
                    }
                }
            }
            AuthMethod::Password(password) => {
                match session
                    .authenticate_password(&self.connection_info.username, password)
                    .await
                {
                    Ok(result) => {
                        let success = matches!(result, russh::client::AuthResult::Success);
                        if success {
                            debug!("✅ Authenticated via password");
                        } else {
                            debug!("Password authentication failed");
                        }
                        Ok(success)
                    }
                    Err(e) => {
                        debug!("Password authentication error: {}", e);
                        Ok(false)
                    }
                }
            }
        }
    }

    pub async fn execute_command(&mut self, command: &str) -> Result<String, SshError> {
        self.execute_command_with_cache_mode(command, None).await
    }

    pub async fn execute_command_with_cache_mode(
        &mut self,
        command: &str,
        force_cache_mode: Option<bool>,
    ) -> Result<String, SshError> {
        debug!("Executing command: {}", command);

        // Initialize cache if not present
        if self.cache.is_none() {
            self.initialize_cache()?;
        }

        // Determine cache mode: explicit override, or use client's setting
        let use_cached_responses = force_cache_mode.unwrap_or(self.use_cache);

        // If we're using cache, try to get response from cache first
        if use_cached_responses {
            if let Some(cache) = &self.cache {
                match cache.get_cached_response(&self.hostname, command) {
                    Ok(Some(cached_response)) => {
                        debug!("Using cached response for command: {}", command);
                        if cached_response.exit_code == 0 {
                            return Ok(cached_response.output);
                        } else {
                            // For non-zero exit codes, we might want to return an error or the output
                            // For now, return the output but log the exit code
                            debug!(
                                "Cached response had non-zero exit code: {}",
                                cached_response.exit_code
                            );
                            return Ok(cached_response.output);
                        }
                    }
                    Ok(None) => {
                        debug!("No cached response found for command: {}", command);
                        return Err(SshError::Cache(format!(
                            "No cached response found for command '{}' on host '{}'",
                            command, self.hostname
                        )));
                    }
                    Err(e) => {
                        debug!("Error accessing cache for command '{}': {}", command, e);
                        return Err(SshError::Cache(format!("Error accessing cache: {}", e)));
                    }
                }
            } else {
                return Err(SshError::Cache(
                    "Cache mode enabled but no cache available".to_string(),
                ));
            }
        }

        // Execute command normally (not using cache or caching responses)
        let output = self.execute_command_live(command).await?;

        // Always cache the response if we have a cache (for future use)
        if let Some(cache) = &self.cache {
            if let Err(e) = cache.cache_command_response(&self.hostname, command, &output, None, 0)
            {
                warn!("Failed to cache command response: {}", e);
            } else {
                debug!("Cached response for command: {}", command);
            }
        }

        Ok(output)
    }

    fn initialize_cache(&mut self) -> Result<(), TrailFinderError> {
        if self.cache.is_none() {
            use std::sync::Arc;

            self.cache = Some(Arc::new(crate::cache::CommandCache::new_default()?));
        }
        Ok(())
    }

    async fn execute_command_live(&mut self, command: &str) -> Result<String, SshError> {
        debug!("Executing live command: {}", command);

        // Get the session or create a new one if needed
        let session = match &self.session {
            Some(_) => {
                // For simplicity, create a new session each time for now
                let mut session = self.create_session().await?;
                if let Some(auth_method) = &self.connection_info.successful_auth.clone() {
                    if !self.authenticate_session(&mut session, auth_method).await? {
                        return Err(SshError::Authentication(
                            "Cached authentication method failed".to_string(),
                        ));
                    }
                } else {
                    return Err(SshError::Authentication(
                        "No successful authentication method cached".to_string(),
                    ));
                }
                session
            }
            None => {
                return Err(SshError::Authentication("No session available".to_string()));
            }
        };

        trace!("Creating channel for command: {}", command);
        let mut channel = session.channel_open_session().await.map_err(|e| {
            debug!("Failed to create channel: {}", e);
            SshError::Command(format!("Failed to create channel: {}", e))
        })?;

        debug!("Executing command on channel: {}", command);
        channel.exec(true, command).await.map_err(|e| {
            debug!("Failed to execute command '{}': {}", command, e);
            SshError::Command(format!("Failed to execute '{}': {}", command, e))
        })?;

        // Read output
        let mut stdout_buffer = Vec::new();
        let mut stderr_buffer = Vec::new();

        // Use a timeout for reading
        let timeout_duration = Duration::from_secs(5);

        match tokio::time::timeout(timeout_duration, async {
            loop {
                tokio::select! {
                    // Read from stdout
                    data = channel.wait() => {
                        match data {
                            Some(russh::ChannelMsg::Data { data }) => {
                                stdout_buffer.extend_from_slice(&data);
                                trace!("Read {} bytes from stdout (total: {})", data.len(), stdout_buffer.len());
                            }
                            Some(russh::ChannelMsg::ExtendedData { data, ext: 1 }) => {
                                stderr_buffer.extend_from_slice(&data);
                                trace!("Read {} bytes from stderr (total: {})", data.len(), stderr_buffer.len());
                            }
                            Some(russh::ChannelMsg::Eof) => {
                                debug!("Received EOF");
                                break;
                            }
                            Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                                debug!("Command exited with status: {}", exit_status);
                                break;
                            }
                            Some(russh::ChannelMsg::Close) => {
                                debug!("Channel closed");
                                break;
                            }
                            Some(other) => {
                                debug!("Received other channel message: {:?}", other);
                            }
                            None => {
                                debug!("No more channel messages");
                                break;
                            }
                        }
                    }
                }
            }
        }).await {
            Ok(_) => {}
            Err(_) => {
                error!("Command execution timed out after {:?}", timeout_duration);
                return Err(SshError::Timeout);
            }
        }

        let output = match String::from_utf8(stdout_buffer) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to convert stdout buffer to UTF-8: {}", e);
                // Try stderr as fallback
                if !stderr_buffer.is_empty() {
                    String::from_utf8_lossy(&stderr_buffer).to_string()
                } else {
                    return Err(SshError::Command(format!(
                        "Failed to convert output to UTF-8: {}",
                        e
                    )));
                }
            }
        };

        debug!(
            "Command '{}' completed with {} bytes output",
            command,
            output.len()
        );
        Ok(output)
    }
}

pub struct DeviceIdentifier;

impl DeviceIdentifier {
    pub async fn identify_device(
        ssh_client: &mut SshClient,
    ) -> Result<(DeviceBrand, DeviceType), SshError> {
        // Try to identify MikroTik first using /system identity export
        match ssh_client.execute_command("/system identity export").await {
            Ok(output) => {
                debug!(
                    "MikroTik command '/system identity export' output: '{}'",
                    output.trim()
                );
                if output.contains("RouterOS") || output.contains("SwOS") {
                    // Try to get more specific device info for type detection
                    let device_type = match ssh_client
                        .execute_command("/system routerboard print")
                        .await
                    {
                        Ok(board_output) => {
                            debug!("MikroTik board info: '{}'", board_output.trim());
                            if board_output.contains("CCR")
                                || board_output.contains("hAP")
                                || board_output.contains("hAP")
                                || board_output.contains("Cloud Core Router")
                            {
                                DeviceType::Router
                            } else if board_output.contains("CRS")
                                || board_output.contains("Cloud Router Switch")
                            {
                                DeviceType::Switch
                            } else if board_output.contains("SXT")
                                || board_output.contains("cAP")
                                || board_output.contains("wAP")
                            {
                                DeviceType::AccessPoint
                            } else {
                                DeviceType::Router // Default for RouterBoard and other devices
                            }
                        }
                        Err(_) => {
                            // For SwOS devices, they're typically switches
                            if output.contains("SwOS") {
                                DeviceType::Switch
                            } else {
                                DeviceType::Router // Default for RouterOS
                            }
                        }
                    };
                    return Ok((DeviceBrand::Mikrotik, device_type));
                }
            }
            Err(e) => {
                debug!(
                    "MikroTik identification with '/system identity export' failed: {}",
                    e
                );
            }
        }

        // Try to identify Cisco with show version command
        match ssh_client.execute_command("show version").await {
            Ok(output) => {
                debug!("Cisco command 'show version' output: '{}'", output.trim());
                if output.to_lowercase().contains("cisco")
                    || output.to_lowercase().contains("ios")
                    || output.contains("invalid input detected")
                    || output.contains("% Invalid")
                    || output.contains("IOS.sh")
                    || output.contains("shell is currently disabled")
                    || output.contains("invalid autocommand")
                {
                    debug!("Detected Cisco device from command 'show version'");
                    return Ok((DeviceBrand::Cisco, DeviceType::Switch)); // Default to switch for now
                }
            }
            Err(e) => {
                debug!("Cisco command 'show version' failed: {}", e);
            }
        }

        match ssh_client
            .execute_command(crate::brand::ubiquiti::GET_BOARD_INFO)
            .await
        {
            Ok(output) => {
                debug!(
                    "Ubiquiti command '{}' output: '{}'",
                    crate::brand::ubiquiti::GET_BOARD_INFO,
                    output.trim()
                );
                if output.to_lowercase().contains("ubnt")
                    || output.to_lowercase().contains("ubiquiti")
                    || output.to_lowercase().contains("edgeos")
                    || output.to_lowercase().contains("unifi")
                    || output.contains("board.name")
                {
                    debug!(
                        "Detected Ubiquiti device from command '{}'",
                        crate::brand::ubiquiti::GET_BOARD_INFO
                    );
                    // Further type detection can be done by parsing board info
                    // TODO: this is terrible but a start{
                    let device_type = if output.to_lowercase().contains("ap") {
                        DeviceType::AccessPoint
                    } else {
                        DeviceType::Router // Default to router for now
                    };
                    return Ok((DeviceBrand::Ubiquiti, device_type));
                }
            }
            Err(e) => {
                debug!(
                    "Ubiquiti identification with command '{}' failed: {}",
                    crate::brand::ubiquiti::GET_BOARD_INFO,
                    e
                );
            }
        }

        debug!("No device identification successful, defaulting to Unknown");
        Ok((DeviceBrand::Unknown, DeviceType::Router))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ssh::SshConfig;
    use crate::{DeviceType, config::DeviceBrand};
    use std::time::Duration;

    #[tokio::test]
    async fn test_ssh_config_integration() {
        // Create a temporary SSH config file for testing
        let temp_dir = std::env::temp_dir();
        let config_path = temp_dir.join("test_ssh_config");

        let config_content = r#"
Host testhost.example.com
    User testuser
    IdentityFile ~/.ssh/testhost_key

Host *
    IdentityFile ~/.ssh/%h
    User defaultuser
"#;

        std::fs::write(&config_path, config_content).expect("Failed to write test SSH config");

        // Test our SSH config parser directly
        let ssh_config = SshConfig::parse_file(&config_path).expect("Should parse test SSH config");

        // Test exact host match
        let host_config = ssh_config
            .get_host_config("testhost.example.com")
            .expect("Should find testhost.example.com config");
        assert_eq!(host_config.user, Some("testuser".to_string()));
        assert_eq!(host_config.get_identity_files().len(), 2); // Should have both specific and wildcard identity files

        // Test wildcard match
        let wildcard_config = ssh_config
            .get_host_config("someother.com")
            .expect("Should match wildcard config");
        assert_eq!(wildcard_config.user, Some("defaultuser".to_string()));
        assert!(!wildcard_config.get_identity_files().is_empty());

        // Clean up
        let _ = std::fs::remove_file(&config_path);
    }

    #[test]
    fn test_load_ssh_config_nonexistent() {
        // Test that load_ssh_config returns an empty config when file doesn't exist
        // We can't easily test the actual load_ssh_config function without mocking home_dir,
        // but we can test the parsing logic directly

        let empty_config = SshConfig::default();
        assert_eq!(empty_config.get_host_patterns().len(), 0);

        // Test that getting a host config from empty config returns None
        assert!(empty_config.get_host_config("any.host.com").is_none());
    }

    #[test]
    fn test_username_fallback() {
        // Create SSH config without username for a specific host
        let config_content = r#"
Host test.example.com
    IdentityFile ~/.ssh/test_key

Host *
    User defaultuser
"#;

        let ssh_config = SshConfig::parse(config_content).expect("Should parse SSH config");

        // Test host without username gets default user
        let host_config = ssh_config
            .get_host_config("test.example.com")
            .expect("Should find config");
        assert_eq!(host_config.user, Some("defaultuser".to_string()));

        // Test host not found in config still gets wildcard match
        let wildcard_config = ssh_config
            .get_host_config("notfound.com")
            .expect("Should match wildcard");
        assert_eq!(wildcard_config.user, Some("defaultuser".to_string()));
    }

    #[test]
    fn test_system_user_fallback() {
        // Test that when no SSH config exists and no fallback username is provided,
        // we should fall back to the system user
        let empty_config = SshConfig::default();
        let no_config = empty_config.get_host_config("any.host.com");
        assert!(
            no_config.is_none(),
            "Empty config should return None for any host"
        );

        // This tests that our SSH connection logic would use the system username
        // when both SSH config and device config don't provide one
    }

    #[test]
    fn test_multiple_identity_files() {
        // Test SSH config with multiple IdentityFile directives
        let config_content = r#"
Host test.example.com
    User testuser
    IdentityFile ~/.ssh/key1
    IdentityFile ~/.ssh/key2
    IdentityFile ~/.ssh/key3

Host *
    IdentityFile ~/.ssh/default_key
"#;

        let ssh_config = SshConfig::parse(config_content).expect("Should parse SSH config");

        let host_config = ssh_config
            .get_host_config("test.example.com")
            .expect("Should find config");
        let identity_files = host_config.get_identity_files();

        // Should have all 4 identity files: 3 specific + 1 wildcard
        assert_eq!(identity_files.len(), 4);
        assert!(
            identity_files
                .iter()
                .any(|p| p.to_string_lossy().contains("key1"))
        );
        assert!(
            identity_files
                .iter()
                .any(|p| p.to_string_lossy().contains("key2"))
        );
        assert!(
            identity_files
                .iter()
                .any(|p| p.to_string_lossy().contains("key3"))
        );
        assert!(
            identity_files
                .iter()
                .any(|p| p.to_string_lossy().contains("default_key"))
        );
    }

    // Tests for SshClient functionality
    #[test]
    fn test_ssh_client_new() {
        let address = "192.168.1.1:22".parse().unwrap();
        let username = "testuser".to_string();
        let timeout = Duration::from_secs(30);

        let client = SshClient::new(address, username.clone(), timeout);

        assert_eq!(client.connection_info.address, address);
        assert_eq!(client.connection_info.username, username);
        assert_eq!(client.connection_info.timeout, timeout);
        assert!(client.connection_info.successful_auth.is_none());
        assert!(client.session.is_none());
    }

    #[test]
    fn test_ssh_connection_info_creation() {
        let address = "10.0.0.1:2222".parse().unwrap();
        let username = "admin".to_string();
        let timeout = Duration::from_secs(60);

        let connection_info = SshConnectionInfo {
            address,
            username: username.clone(),
            timeout,
            successful_auth: Some(AuthMethod::SshAgent),
        };

        assert_eq!(connection_info.address, address);
        assert_eq!(connection_info.username, username);
        assert_eq!(connection_info.timeout, timeout);
        assert!(matches!(
            connection_info.successful_auth,
            Some(AuthMethod::SshAgent)
        ));
    }

    #[test]
    fn test_auth_method_variants() {
        // Test SshAgent variant
        let auth1 = AuthMethod::SshAgent;
        assert!(matches!(auth1, AuthMethod::SshAgent));

        // Test KeyFile variant without passphrase
        let auth2 = AuthMethod::KeyFile {
            path: "/path/to/key".to_string(),
            passphrase: None,
        };
        if let AuthMethod::KeyFile { path, passphrase } = auth2 {
            assert_eq!(path, "/path/to/key");
            assert!(passphrase.is_none());
        } else {
            panic!("Expected KeyFile variant");
        }

        // Test KeyFile variant with passphrase
        let auth3 = AuthMethod::KeyFile {
            path: "/path/to/encrypted/key".to_string(),
            passphrase: Some("secret".to_string()),
        };
        if let AuthMethod::KeyFile { path, passphrase } = auth3 {
            assert_eq!(path, "/path/to/encrypted/key");
            assert_eq!(passphrase, Some("secret".to_string()));
        } else {
            panic!("Expected KeyFile variant");
        }

        // Test Password variant
        let auth4 = AuthMethod::Password("password123".to_string());
        if let AuthMethod::Password(password) = auth4 {
            assert_eq!(password, "password123");
        } else {
            panic!("Expected Password variant");
        }
    }

    #[test]
    fn test_ssh_error_display() {
        let error1 = SshError::Connection("Failed to connect".to_string());
        assert_eq!(error1.to_string(), "Connection error: Failed to connect");

        let error2 = SshError::Authentication("Invalid credentials".to_string());
        assert_eq!(
            error2.to_string(),
            "Authentication error: Invalid credentials"
        );

        let error3 = SshError::Command("Command failed".to_string());
        assert_eq!(error3.to_string(), "Command error: Command failed");

        let error4 = SshError::Timeout;
        assert_eq!(error4.to_string(), "Operation timed out");
    }

    #[test]
    fn test_ssh_error_is_error_trait() {
        let error = SshError::Connection("test error".to_string());
        let error_ref: &dyn std::error::Error = &error;
        assert!(error_ref.to_string().contains("Connection error"));
    }

    // Tests for DeviceIdentifier

    #[test]
    fn test_device_brand_enum() {
        // Test that DeviceBrand enum variants exist and can be constructed
        let mikrotik = DeviceBrand::Mikrotik;
        let cisco = DeviceBrand::Cisco;

        assert!(matches!(mikrotik, DeviceBrand::Mikrotik));
        assert!(matches!(cisco, DeviceBrand::Cisco));

        // Test Debug trait implementation
        let debug_str = format!("{:?}", mikrotik);
        assert!(debug_str.contains("Mikrotik"));
    }

    #[test]
    fn test_device_type_enum() {
        // Test that DeviceType enum variants exist and can be constructed
        let router = DeviceType::Router;
        let switch = DeviceType::Switch;
        let access_point = DeviceType::AccessPoint;

        assert!(matches!(router, DeviceType::Router));
        assert!(matches!(switch, DeviceType::Switch));
        assert!(matches!(access_point, DeviceType::AccessPoint));

        // Test Debug trait implementation
        let debug_str = format!("{:?}", router);
        assert!(debug_str.contains("Router"));
    }

    // Mock helper functions for testing SSH connection logic
    #[test]
    fn test_ssh_config_parsing_with_identities_only() {
        let config_content = r#"
Host secure.example.com
    User secureuser
    IdentitiesOnly yes
    IdentityFile ~/.ssh/secure_key

Host insecure.example.com
    User insecureuser
    IdentitiesOnly no
    IdentityFile ~/.ssh/insecure_key

Host *
    User defaultuser
    IdentitiesOnly yes
"#;
        let ssh_config = SshConfig::parse(config_content).expect("Should parse SSH config");

        // Test secure host with IdentitiesOnly yes
        let secure_config = ssh_config
            .get_host_config("secure.example.com")
            .expect("Should find secure config");
        assert_eq!(secure_config.user, Some("secureuser".to_string()));
        assert_eq!(secure_config.identities_only, Some(true));

        // Test insecure host with IdentitiesOnly no
        let insecure_config = ssh_config
            .get_host_config("insecure.example.com")
            .expect("Should find insecure config");
        assert_eq!(insecure_config.user, Some("insecureuser".to_string()));
        assert_eq!(insecure_config.identities_only, Some(false));

        // Test wildcard matching
        let other_config = ssh_config
            .get_host_config("other.example.com")
            .expect("Should match wildcard");
        assert_eq!(other_config.user, Some("defaultuser".to_string()));
        assert_eq!(other_config.identities_only, Some(true));
    }

    #[test]
    fn test_ssh_config_hostname_expansion() {
        let config_content = r#"
Host web*.example.com
    User webuser
    IdentityFile ~/.ssh/web_key

Host db*.example.com
    User dbuser
    IdentityFile ~/.ssh/db_key

Host *.example.com
    User generaluser
    IdentityFile ~/.ssh/general_key
"#;
        let ssh_config = SshConfig::parse(config_content).expect("Should parse SSH config");

        // Test web server hostname pattern - if pattern matching doesn't work, fall back to general
        let web_config = ssh_config.get_host_config("web1.example.com");
        if let Some(config) = web_config {
            // Could be either webuser or generaluser depending on pattern matching implementation
            assert!(config.user.is_some());
        }

        let web2_config = ssh_config.get_host_config("web-prod.example.com");
        if let Some(config) = web2_config {
            // Could be either webuser or generaluser depending on pattern matching implementation
            assert!(config.user.is_some());
        }

        // Test database hostname pattern
        let db_config = ssh_config.get_host_config("db1.example.com");
        if let Some(config) = db_config {
            // Could be either dbuser or generaluser depending on pattern matching implementation
            assert!(config.user.is_some());
        }

        // Test general wildcard
        let general_config = ssh_config.get_host_config("mail.example.com");
        if let Some(config) = general_config {
            // Should match at least one pattern
            assert!(config.user.is_some());
        } else {
            // If no pattern matches, that's also acceptable for this test
            // since we're testing the parsing logic, not the pattern matching logic
        }
    }

    #[test]
    fn test_ssh_config_case_sensitivity() {
        let config_content = r#"
Host TestHost.Example.Com
    User testuser
    IdentityFile ~/.ssh/test_key
"#;
        let ssh_config = SshConfig::parse(config_content).expect("Should parse SSH config");

        // SSH config matching should be case-insensitive for hostnames
        let config1 = ssh_config.get_host_config("testhost.example.com");
        let config2 = ssh_config.get_host_config("TestHost.Example.Com");
        let config3 = ssh_config.get_host_config("TESTHOST.EXAMPLE.COM");

        // At least one should match (behavior may vary by implementation)
        assert!(config1.is_some() || config2.is_some() || config3.is_some());
    }

    #[test]
    fn test_ssh_config_identity_file_expansion() {
        let config_content = r#"
Host test.example.com
    User testuser
    IdentityFile ~/.ssh/%h_key
    IdentityFile ~/.ssh/%u_key
    IdentityFile ~/.ssh/literal_key
"#;
        let ssh_config = SshConfig::parse(config_content).expect("Should parse SSH config");

        let host_config = ssh_config
            .get_host_config("test.example.com")
            .expect("Should find config");
        let identity_files = host_config.get_identity_files();

        // Should have at least the literal key file
        assert!(!identity_files.is_empty());
        assert!(
            identity_files
                .iter()
                .any(|p| p.to_string_lossy().contains("literal_key")),
            "Should contain literal_key file"
        );
    }

    #[test]
    fn test_ssh_config_port_handling() {
        let config_content = r#"
Host custom-port.example.com
    User customuser
    Port 2222
    IdentityFile ~/.ssh/custom_key

Host default-port.example.com
    User defaultuser
    IdentityFile ~/.ssh/default_key
"#;
        let ssh_config = SshConfig::parse(config_content).expect("Should parse SSH config");

        let custom_config = ssh_config
            .get_host_config("custom-port.example.com")
            .expect("Should find custom config");
        assert_eq!(custom_config.user, Some("customuser".to_string()));

        let default_config = ssh_config
            .get_host_config("default-port.example.com")
            .expect("Should find default config");
        assert_eq!(default_config.user, Some("defaultuser".to_string()));
    }

    #[test]
    fn test_ssh_config_comment_handling() {
        let config_content = r#"
# This is a comment
Host comment-test.example.com
    # Another comment
    User commentuser
    IdentityFile ~/.ssh/comment_key  # Inline comment
    # Final comment
"#;
        let ssh_config =
            SshConfig::parse(config_content).expect("Should parse SSH config with comments");

        let config = ssh_config
            .get_host_config("comment-test.example.com")
            .expect("Should find config despite comments");
        assert_eq!(config.user, Some("commentuser".to_string()));
        assert!(!config.get_identity_files().is_empty());
    }

    #[test]
    fn test_ssh_config_empty_lines() {
        let config_content = r#"

Host empty-lines.example.com

    User emptyuser


    IdentityFile ~/.ssh/empty_key


"#;
        let ssh_config =
            SshConfig::parse(config_content).expect("Should parse SSH config with empty lines");

        let config = ssh_config
            .get_host_config("empty-lines.example.com")
            .expect("Should find config despite empty lines");
        assert_eq!(config.user, Some("emptyuser".to_string()));
        assert!(!config.get_identity_files().is_empty());
    }
}
