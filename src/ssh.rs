use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    time::Duration,
};

use ssh_config::SSHConfig;
use ssh2::Session;
use tracing::debug;

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

impl SshClient {
    pub fn connect_with_ssh_config(
        hostname: &str,
        ip_address: SocketAddr,
        timeout: Duration,
    ) -> Result<Self, SshError> {
        // Load SSH config
        let ssh_config = Self::load_ssh_config()?;
        let host_config = ssh_config.query(hostname);

        // Get connection details from SSH config
        let username = host_config
            .get("User")
            .or_else(|| host_config.get("user"))
            .ok_or_else(|| SshError::Authentication("No username in SSH config".to_string()))?;

        let identities_only = host_config
            .get("IdentitiesOnly")
            .or_else(|| host_config.get("identitiesonly"))
            .map(|v| v.to_lowercase() == "yes")
            .unwrap_or(false);
        let use_ssh_agent = !identities_only;

        // Get identity files from config
        let identity_file = host_config
            .get("IdentityFile")
            .or_else(|| host_config.get("identityfile"));

        let identity_files: Vec<PathBuf> = if let Some(id_file) = identity_file {
            vec![if let Some(stripped) = id_file.strip_prefix("~/") {
                if let Some(home_dir) = dirs::home_dir() {
                    home_dir.join(stripped)
                } else {
                    PathBuf::from(id_file)
                }
            } else {
                PathBuf::from(id_file)
            }]
        } else {
            Vec::new()
        };

        let key_path = identity_files
            .first()
            .map(|p| p.to_string_lossy().to_string());

        Self::connect(
            ip_address,
            username,
            None, // no password from config
            key_path.as_deref(),
            None, // no passphrase from SSH config
            use_ssh_agent,
            timeout,
        )
    }

    fn load_ssh_config() -> Result<SSHConfig<'static>, SshError> {
        let ssh_config_path = if let Some(home_dir) = dirs::home_dir() {
            home_dir.join(".ssh").join("config")
        } else {
            return Err(SshError::Connection(
                "Cannot find home directory".to_string(),
            ));
        };

        let config_content = std::fs::read_to_string(&ssh_config_path)
            .map_err(|e| SshError::Connection(format!("Failed to read SSH config: {}", e)))?;

        let leaked_content = Box::leak(config_content.into_boxed_str());

        SSHConfig::parse_str(leaked_content)
            .map_err(|e| SshError::Connection(format!("Failed to parse SSH config: {:?}", e)))
    }

    pub fn connect(
        address: SocketAddr,
        username: &str,
        password: Option<&str>,
        key_path: Option<&str>,
        key_passphrase: Option<&str>,
        use_ssh_agent: bool,
        timeout: Duration,
    ) -> Result<Self, SshError> {
        let mut client = Self::new(address, username.to_string(), timeout);

        // Attempt authentication to find working method
        client.discover_auth_method(password, key_path, key_passphrase, use_ssh_agent)?;

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
        }
    }

    fn create_session(&self) -> Result<Session, SshError> {
        let tcp =
            TcpStream::connect_timeout(&self.connection_info.address, self.connection_info.timeout)
                .map_err(|e| SshError::Connection(e.to_string()))?;

        let mut session = Session::new().map_err(|e| SshError::Connection(e.to_string()))?;
        session.set_tcp_stream(tcp);

        // Configure SSH methods to support legacy RSA algorithms
        session
            .method_pref(
                ssh2::MethodType::HostKey,
                "rsa-sha2-512,rsa-sha2-256,ssh-rsa",
            )
            .map_err(|e| {
                debug!("Failed to set hostkey methods: {}", e);
            })
            .ok();

        session.method_pref(ssh2::MethodType::Kex, "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1")
            .map_err(|e| {
                debug!("Failed to set key exchange methods: {}", e);
            }).ok();

        session
            .handshake()
            .map_err(|e| SshError::Connection(e.to_string()))?;

        Ok(session)
    }

    fn discover_auth_method(
        &mut self,
        password: Option<&str>,
        key_path: Option<&str>,
        key_passphrase: Option<&str>,
        use_ssh_agent: bool,
    ) -> Result<(), SshError> {
        let session = self.create_session()?;

        let auth_methods = vec![
            if use_ssh_agent {
                Some(AuthMethod::SshAgent)
            } else {
                None
            },
            if let Some(path) = key_path {
                Some(AuthMethod::KeyFile {
                    path: path.to_string(),
                    passphrase: key_passphrase.map(String::from),
                })
            } else {
                None
            },
            if let Some(pwd) = password {
                Some(AuthMethod::Password(pwd.to_string()))
            } else {
                None
            },
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

        for auth_method in auth_methods {
            if self.authenticate_session(&session, &auth_method)? {
                self.connection_info.successful_auth = Some(auth_method);
                return Ok(());
            }
        }

        Err(SshError::Authentication(
            "All authentication methods failed".to_string(),
        ))
    }

    fn authenticate_session(
        &self,
        session: &Session,
        auth_method: &AuthMethod,
    ) -> Result<bool, SshError> {
        match auth_method {
            AuthMethod::SshAgent => match session.userauth_agent(&self.connection_info.username) {
                Ok(()) => {
                    let authenticated = session.authenticated();
                    if authenticated {
                        debug!("✅ Authenticated via ssh-agent");
                    } else {
                        debug!("ssh-agent authentication succeeded but session not authenticated");
                    }
                    Ok(authenticated)
                }
                Err(e) => {
                    debug!("ssh-agent authentication failed: {}", e);
                    Ok(false)
                }
            },
            AuthMethod::KeyFile { path, passphrase } => {
                let expanded_path = shellexpand::tilde(path);
                let key_path_buf = std::path::Path::new(expanded_path.as_ref());

                if !key_path_buf.exists() {
                    debug!("SSH key file does not exist: {}", expanded_path);
                    return Ok(false);
                }

                match session.userauth_pubkey_file(
                    &self.connection_info.username,
                    None,
                    key_path_buf,
                    passphrase.as_deref(),
                ) {
                    Ok(()) => {
                        let authenticated = session.authenticated();
                        if authenticated {
                            debug!("✅ Authenticated via key file: {}", expanded_path);
                        } else {
                            debug!(
                                "Key file authentication succeeded but session not authenticated: {}",
                                expanded_path
                            );
                        }
                        Ok(authenticated)
                    }
                    Err(e) => {
                        debug!("Key file authentication failed: {}", e);
                        Ok(false)
                    }
                }
            }
            AuthMethod::Password(password) => {
                match session.userauth_password(&self.connection_info.username, password) {
                    Ok(()) => {
                        let authenticated = session.authenticated();
                        if authenticated {
                            debug!("✅ Authenticated via password");
                        } else {
                            debug!(
                                "Password authentication succeeded but session not authenticated"
                            );
                        }
                        Ok(authenticated)
                    }
                    Err(e) => {
                        debug!("Password authentication failed: {}", e);
                        Ok(false)
                    }
                }
            }
        }
    }

    pub fn execute_command(&mut self, command: &str) -> Result<String, SshError> {
        debug!("Executing command: {}", command);

        // Create a fresh session for this command
        let session = self.create_session()?;
        session.trace(ssh2::TraceFlags::all());

        // Re-authenticate using the cached successful method
        if let Some(auth_method) = &self.connection_info.successful_auth.clone() {
            if !self.authenticate_session(&session, auth_method)? {
                return Err(SshError::Authentication(
                    "Cached authentication method failed".to_string(),
                ));
            }
            // Give the session a moment to fully establish
            std::thread::sleep(std::time::Duration::from_millis(100));
        } else {
            return Err(SshError::Authentication(
                "No successful authentication method cached".to_string(),
            ));
        }

        debug!("Creating channel session for command: {}", command);
        let mut channel = session.channel_session().map_err(|e| {
            debug!("Failed to create channel session: {}", e);
            SshError::Command(format!("Failed to create channel session: {}", e))
        })?;

        debug!("Executing command on channel: {}", command);
        channel.exec(command).map_err(|e| {
            debug!("Failed to execute command '{}': {}", command, e);
            SshError::Command(format!("Failed to execute '{}': {}", command, e))
        })?;

        // Give the command a moment to execute before reading
        std::thread::sleep(std::time::Duration::from_millis(200));
        channel.flush().map_err(|err| {
            debug!("Failed to flush channel: {}", err);
            SshError::Command(format!("Failed to flush channel: {}", err))
        })?;

        debug!("Reading command output for: {}", command);

        // Wait for command output with timeout
        let mut stdout_buffer = Vec::new();
        let mut stderr_buffer = Vec::new();
        let timeout = std::time::Duration::from_secs(5); // Use 5 second timeout for identification
        let start_time = std::time::Instant::now();

        debug!("Waiting up to {:?} for command output", timeout);

        // Poll for data with timeout
        while start_time.elapsed() < timeout {
            // Try to read stderr
            let mut temp_stderr = Vec::new();
            match channel.stderr().read_to_end(&mut temp_stderr) {
                Ok(bytes_read) => {
                    if bytes_read > 0 {
                        stderr_buffer.extend_from_slice(&temp_stderr);
                        debug!(
                            "Read {} bytes from stderr (total: {})",
                            bytes_read,
                            stderr_buffer.len()
                        );
                    }
                }
                Err(e) => {
                    debug!("Stderr read attempt: {}", e);
                }
            }

            // Try to read stdout
            let mut temp_stdout = Vec::new();
            match channel.read_to_end(&mut temp_stdout) {
                Ok(bytes_read) => {
                    if bytes_read > 0 {
                        stdout_buffer.extend_from_slice(&temp_stdout);
                        debug!(
                            "Read {} bytes from stdout (total: {})",
                            bytes_read,
                            stdout_buffer.len()
                        );
                    }
                    // If we got data, we might be done
                    if bytes_read > 0 || (!stdout_buffer.is_empty() && channel.eof()) {
                        break;
                    }
                }
                Err(e) => {
                    debug!("Stdout read attempt: {}", e);
                }
            }

            // If we have data from either stream, check if channel is done
            if !stdout_buffer.is_empty() || !stderr_buffer.is_empty() {
                debug!("Got data and channel EOF, breaking");
                break;
            }

            // Small delay to avoid busy waiting
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        debug!(
            "Finished reading after {:?} - stdout: {} bytes, stderr: {} bytes",
            start_time.elapsed(),
            stdout_buffer.len(),
            stderr_buffer.len()
        );

        let output = match String::from_utf8(stdout_buffer) {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to convert stdout buffer to UTF-8: {}", e);
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

        debug!("Waiting for channel close");
        match channel.wait_close() {
            Ok(_) => {
                debug!("Channel closed successfully");
            }
            Err(e) => {
                debug!("Error waiting for channel close: {}", e);
                // Don't fail on close error if we got output
            }
        }

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
    pub fn identify_device(
        ssh_client: &mut SshClient,
    ) -> Result<(DeviceBrand, DeviceType), SshError> {
        // First try basic commands to see if the device responds at all
        // let basic_commands = ["echo test", "whoami", "pwd", "uname -a"];
        // for cmd in basic_commands {
        //     match ssh_client.execute_command(cmd) {
        //         Ok(output) => {
        //             debug!(
        //                 "Command '{}' succeeded with output: '{}'",
        //                 cmd,
        //                 output.trim()
        //             );
        //             // Check if this is a Cisco IOS device based on shell disabled message
        //             if output.contains("IOS.sh") || output.contains("shell is currently disabled") {
        //                 debug!("Detected Cisco IOS device from basic command '{}'", cmd);
        //                 return Ok((DeviceBrand::Cisco, DeviceType::Switch));
        //             }
        //             break;
        //         }
        //         Err(e) => {
        //             debug!("Command '{}' failed: {}", cmd, e);
        //         }
        //     }
        // }

        // Try to identify MikroTik first
        match ssh_client.execute_command("/system health print") {
            Ok(output) => {
                debug!("MikroTik command output: '{}'", output.trim());
                if output.contains("MikroTik") || output.contains("RouterOS") {
                    let device_type =
                        if output.contains("CCR") || output.contains("Cloud Core Router") {
                            DeviceType::Router
                        } else if output.contains("CRS") || output.contains("Cloud Router Switch") {
                            DeviceType::Switch
                        } else if output.contains("hAP") || output.contains("SXT") {
                            DeviceType::AccessPoint
                        } else {
                            DeviceType::Router // Default for MikroTik
                        };
                    return Ok((DeviceBrand::Mikrotik, device_type));
                }
            }
            Err(e) => {
                debug!("MikroTik identification failed: {}", e);
            }
        }

        // Try to identify Cisco with show version command
        match ssh_client.execute_command("show version") {
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

        // // Try to identify Ubiquiti
        // match ssh_client.execute_command("mca-cli") {
        //     Ok(output) => {
        //         debug!("Ubiquiti command output: '{}'", output.trim());
        //         if output.contains("UniFi") || output.contains("Ubiquiti") {
        //             return Ok((DeviceBrand::Ubiquiti, DeviceType::AccessPoint));
        //         }
        //     }
        //     Err(e) => {
        //         debug!("Ubiquiti identification failed: {}", e);
        //     }
        // }

        debug!("No device identification successful, defaulting to Unknown");
        Ok((DeviceBrand::Unknown, DeviceType::Router))
    }
}
