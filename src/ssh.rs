use std::{
    io::Read,
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    time::Duration,
};

use ssh2::Session;
use ssh_config::SSHConfig;

use crate::{config::DeviceBrand, DeviceType};

pub struct SshClient {
    session: Session,
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
        let use_ssh_agent = !identities_only; // if IdentitiesOnly=yes, don't use ssh-agent

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

        let key_path = identity_files.first().map(|p| p.to_string_lossy().to_string());
        
        Self::connect(
            ip_address,
            username,
            None, // no password from config
            key_path.as_deref(),
            use_ssh_agent,
            timeout,
        )
    }

    fn load_ssh_config() -> Result<SSHConfig<'static>, SshError> {
        let ssh_config_path = if let Some(home_dir) = dirs::home_dir() {
            home_dir.join(".ssh").join("config")
        } else {
            return Err(SshError::Connection("Cannot find home directory".to_string()));
        };

        let config_content = std::fs::read_to_string(&ssh_config_path)
            .map_err(|e| SshError::Connection(format!("Failed to read SSH config: {}", e)))?;
        
        // We need to leak the string to get a static lifetime - this is a limitation of the library
        let leaked_content = Box::leak(config_content.into_boxed_str());
        
        SSHConfig::parse_str(leaked_content)
            .map_err(|e| SshError::Connection(format!("Failed to parse SSH config: {:?}", e)))
    }

    pub fn connect(
        address: SocketAddr,
        username: &str,
        password: Option<&str>,
        key_path: Option<&str>,
        use_ssh_agent: bool,
        timeout: Duration,
    ) -> Result<Self, SshError> {
        let tcp = TcpStream::connect_timeout(&address, timeout)
            .map_err(|e| SshError::Connection(e.to_string()))?;

        let mut session = Session::new().map_err(|e| SshError::Connection(e.to_string()))?;
        session.set_tcp_stream(tcp);
        session
            .handshake()
            .map_err(|e| SshError::Connection(e.to_string()))?;

        // Try authentication methods in order: ssh-agent, key file, password
        let mut authenticated = false;
        
        if use_ssh_agent {
            match session.userauth_agent(username) {
                Ok(()) => {
                    authenticated = session.authenticated();
                    if authenticated {
                        println!("  Authenticated via ssh-agent");
                    }
                }
                Err(e) => {
                    println!("  ssh-agent authentication failed: {}", e);
                }
            }
        }

        if !authenticated
            && let Some(key_path) = key_path
        {
            match session.userauth_pubkey_file(username, None, std::path::Path::new(&key_path), None) {
                Ok(()) => {
                    authenticated = session.authenticated();
                    if authenticated {
                        println!("  Authenticated via key file: {}", key_path);
                    }
                }
                Err(e) => {
                    println!("  Key file authentication failed: {}", e);
                }
            }
        }

        if !authenticated
            && let Some(password) = password
        {
            match session.userauth_password(username, password) {
                Ok(()) => {
                    authenticated = session.authenticated();
                    if authenticated {
                        println!("  Authenticated via password");
                    }
                }
                Err(e) => {
                    println!("  Password authentication failed: {}", e);
                }
            }
        }

        if !authenticated {
            return Err(SshError::Authentication(
                "All authentication methods failed".to_string(),
            ));
        }

        Ok(Self { session })
    }

    pub fn execute_command(&mut self, command: &str) -> Result<String, SshError> {
        let mut channel = self
            .session
            .channel_session()
            .map_err(|e| SshError::Command(e.to_string()))?;

        channel
            .exec(command)
            .map_err(|e| SshError::Command(e.to_string()))?;

        let mut output = String::new();
        channel
            .read_to_string(&mut output)
            .map_err(|e| SshError::Command(e.to_string()))?;

        channel
            .wait_close()
            .map_err(|e| SshError::Command(e.to_string()))?;

        Ok(output)
    }
}

pub struct DeviceIdentifier;

impl DeviceIdentifier {
    pub fn identify_device(
        ssh_client: &mut SshClient,
    ) -> Result<(DeviceBrand, DeviceType), SshError> {
        // Try to identify MikroTik first
        if let Ok(output) = ssh_client.execute_command("/system resource print")
            && (output.contains("MikroTik") || output.contains("RouterOS"))
        {
            // Determine device type based on MikroTik model/features
            let device_type = if output.contains("CCR") || output.contains("Cloud Core Router") {
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

        // Try to identify Cisco
        if let Ok(output) = ssh_client.execute_command("show version")
            && output.contains("Cisco")
        {
            let device_type = if output.contains("router") || output.contains("Router") {
                DeviceType::Router
            } else if output.contains("switch") || output.contains("Switch") {
                DeviceType::Switch
            } else if output.contains("ASA") || output.contains("Firewall") {
                DeviceType::Firewall
            } else {
                DeviceType::Router // Default for Cisco
            };

            return Ok((DeviceBrand::Cisco, device_type));
        }

        // Try to identify Ubiquiti
        if let Ok(output) = ssh_client.execute_command("mca-cli")
            && (output.contains("UniFi") || output.contains("Ubiquiti"))
        {
            return Ok((DeviceBrand::Ubiquiti, DeviceType::AccessPoint));
        }

        // Default fallback
        Ok((DeviceBrand::Unknown, DeviceType::Router))
    }
}