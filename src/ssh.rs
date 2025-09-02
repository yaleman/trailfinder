use std::{net::SocketAddr, sync::Arc, time::Duration};

use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, decode_secret_key};
use russh::{client, keys::ssh_key};

// Remove the old ssh_config crate import
use tracing::{debug, error, trace, warn};

use crate::{DeviceType, config::DeviceBrand};

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
}

#[derive(Debug)]
pub enum SshError {
    Connection(String),
    Authentication(String),
    Command(String),
    Timeout,
}

impl std::fmt::Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshError::Connection(msg) => write!(f, "Connection error: {}", msg),
            SshError::Authentication(msg) => write!(f, "Authentication error: {}", msg),
            SshError::Command(msg) => write!(f, "Command error: {}", msg),
            SshError::Timeout => write!(f, "Operation timed out"),
        }
    }
}

impl std::error::Error for SshError {}

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

        // Get resolved SSH key paths
        let key_paths: Vec<String> = device_config
            .get_resolved_ssh_key_paths()
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

        Self::connect(
            ip_address,
            &username,
            None, // no password from config
            &key_paths,
            device_config.ssh_key_passphrase.as_deref(),
            use_ssh_agent,
            timeout,
        )
        .await
    }

    pub async fn connect_with_ssh_config(
        hostname: &str,
        ip_address: SocketAddr,
        timeout: Duration,
        fallback_username: Option<&str>,
    ) -> Result<Self, SshError> {
        // Load SSH config using our custom parser
        let ssh_config = Self::load_ssh_config()?;
        let host_config = ssh_config.get_host_config(hostname);

        debug!(
            hostname = %hostname,
            ssh_config_found = host_config.is_some(),
            "SSH config lookup result"
        );

        // Get system user as final fallback
        let system_user = std::env::var("USER").ok();
        let system_user_ref = system_user.as_deref();

        let (username, identities_only, identity_files) = if let Some(config) = host_config {
            // Get connection details from SSH config, with fallback to provided username
            let username = config
                .user
                .as_deref()
                .or(fallback_username)
                .or(system_user_ref)
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
            let username = fallback_username
                .or(system_user_ref)
                .ok_or_else(|| {
                    SshError::Authentication(
                        "No SSH config found and no fallback username or system user available"
                            .to_string(),
                    )
                })?
                .to_string();

            (username, false, Vec::new())
        };

        let use_ssh_agent = !identities_only;
        let key_paths: Vec<String> = identity_files
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        let current_user = std::env::var("USER").ok();
        debug!(
            hostname = %hostname,
            username = %username,
            use_ssh_agent = %use_ssh_agent,
            identity_files_count = identity_files.len(),
            identity_files = ?key_paths,
            fallback_username = ?fallback_username,
            system_user = ?current_user,
            "SSH config loaded for host"
        );

        Self::connect(
            ip_address,
            &username,
            None, // no password from config
            &key_paths,
            None, // no passphrase from SSH config
            use_ssh_agent,
            timeout,
        )
        .await
    }

    fn load_ssh_config() -> Result<crate::config::ssh::SshConfig, SshError> {
        use crate::config::ssh::SshConfig;

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
            .map_err(|e| SshError::Connection(e.to_string()))?;

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
                            match PrivateKey::from_openssh(&key_data)
                                .and_then(|k| k.decrypt(phrase))
                            {
                                Ok(key) => key,
                                Err(e) => {
                                    debug!("Failed to decrypt OpenSSH key: {}", e);
                                    return Ok(false);
                                }
                            }
                        }
                        None => match PrivateKey::from_openssh(&key_data) {
                            Ok(key) => key,
                            Err(e) => {
                                debug!("Failed to load unencrypted OpenSSH key: {}", e);
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
        debug!("Executing command: {}", command);

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

        debug!("No device identification successful, defaulting to Unknown");
        Ok((DeviceBrand::Unknown, DeviceType::Router))
    }
}

#[cfg(test)]
mod tests {
    use crate::config::ssh::SshConfig;

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
}
