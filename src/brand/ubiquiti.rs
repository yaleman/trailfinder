use super::prelude::*;

#[derive(Default, Debug, Clone)]
pub struct Ubiquiti {
    pub hostname: String,
    pub name: Option<String>,
    pub owner: Owner,
    pub device_type: DeviceType,
    pub routes: Vec<Route>,
    pub interfaces: Vec<Interface>,
    pub system_identity: Option<String>,
    pub ipsec_peers: Vec<IpsecPeer>,
}

pub(crate) const GET_BOARD_INFO: &str = "cat /etc/board.info";

impl DeviceHandler for Ubiquiti {
    const GET_IP_COMMAND: &'static str = "";

    const GET_IDENTITY_COMMAND: &'static str = "cat /proc/sys/kernel/hostname";

    const GET_IPSEC_COMMAND: &'static str = "echo 'not supported'";

    fn new(hostname: String, name: Option<String>, owner: Owner, device_type: DeviceType) -> Self {
        Ubiquiti {
            hostname,
            name,
            owner,
            device_type,
            ..Default::default()
        }
    }

    fn parse_interfaces(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        debug!("Parsing interfaces from input:\n{input_data}");

        let line_start_regex = Regex::new(r#"^(?P<if_index>\d+):\s+(?P<if_name>\S+?)(@\S+)?:"#)?;
        let inet_regex = Regex::new(r#"^\s+inet\s+(?P<ip>\S+)"#)?;
        let link_regex = Regex::new(r#"^\s+link/(?P<link_type>\S+)\s+(?P<mac>\S+)"#)?;

        let mut current_interface: Option<Interface> = None;

        for line in input_data.lines() {
            debug!("Interface line: {}", line);

            if let Some(caps) = line_start_regex.captures(line) {
                // Save previous interface if exists
                if let Some(interface) = current_interface.take() {
                    self.interfaces.push(interface);
                }

                // Start new interface
                let Some(if_name_match) = caps.name("if_name") else {
                    continue;
                };
                let if_name = if_name_match.as_str().to_string();
                let interface_type = if if_name.starts_with("ath") || if_name.starts_with("wifi") {
                    InterfaceType::Other("wireless".to_string())
                } else if if_name.starts_with("br") {
                    InterfaceType::Bridge
                } else if if_name.contains(".") {
                    InterfaceType::Vlan
                } else if if_name == "lo" {
                    InterfaceType::Loopback
                } else {
                    InterfaceType::Ethernet
                };

                current_interface = Some(Interface {
                    interface_id: uuid::Uuid::new_v4(),
                    name: if_name,
                    interface_type,
                    mac_address: None,
                    vlans: Default::default(),
                    addresses: Default::default(),
                    comment: Default::default(),
                    neighbour_string_data: Default::default(),
                    peers: Default::default(),
                });
            } else if let Some(ref mut interface) = current_interface {
                // Parse MAC address
                if let Some(caps) = link_regex.captures(line) {
                    let Some(mac_match) = caps.name("mac") else {
                        continue;
                    };
                    let mac = mac_match.as_str();
                    if mac != "00:00:00:00:00:00"
                        && !mac.contains("void")
                        && let Ok(parsed_mac) = mac.parse()
                    {
                        interface.mac_address = Some(parsed_mac);
                    }
                }

                // Parse IP addresses
                if let Some(caps) = inet_regex.captures(line) {
                    let Some(ip_match) = caps.name("ip") else {
                        continue;
                    };
                    let ip_str = ip_match.as_str();
                    if let Ok(interface_addr) = InterfaceAddress::try_from(ip_str) {
                        interface.addresses.push(interface_addr);
                    }
                }
            }
        }

        // Don't forget the last interface
        if let Some(interface) = current_interface {
            self.interfaces.push(interface);
        }

        info!("Parsed {} interfaces", self.interfaces.len());
        Ok(())
    }

    fn parse_routes(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        for line in input_data.lines() {
            if line.starts_with("default via ") {
                debug!("Default route: {line}");
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let Some(interface_id) = self.interface_by_name(parts[4].trim()) {
                        self.routes.push(Route {
                            route_type: RouteType::Default(interface_id),
                            gateway: Some(parts[2].trim().parse()?),
                            target: "0.0.0.0/0".parse()?,
                            distance: Some(0),
                        });
                        info!(
                            "Added default route via {} on interface {}",
                            parts[2], parts[4]
                        );
                    } else {
                        debug!("Could not find interface for default route: {}", parts[2]);
                    }
                }
            } else {
                debug!("Need to handle this line: {}", line);
            }
        }
        Ok(())
    }

    fn parse_neighbours(
        &mut self,
        input_data: &str,
        _devices: Vec<Device>,
    ) -> Result<usize, TrailFinderError> {
        debug!("Parsing LLDP neighbors from input:\n{input_data}");

        if input_data.trim().is_empty() {
            debug!("No LLDP data to parse");
            return Ok(0);
        }

        let lldp_data: serde_json::Value = match serde_json::from_str(input_data) {
            Ok(data) => data,
            Err(e) => {
                debug!("Failed to parse LLDP JSON: {}", e);
                return Ok(0);
            }
        };

        let mut neighbor_count = 0;

        if let Some(interfaces) = lldp_data["lldp"]["interface"].as_array() {
            for interface_data in interfaces {
                if let Some(interface_obj) = interface_data.as_object() {
                    for (interface_name, interface_info) in interface_obj {
                        debug!("Processing LLDP data for interface: {}", interface_name);

                        if let Some(chassis_info) = interface_info["chassis"].as_object() {
                            for (neighbor_name, neighbor_data) in chassis_info {
                                let mgmt_ip = neighbor_data["mgmt-ip"]
                                    .as_str()
                                    .unwrap_or("unknown")
                                    .to_string();
                                let chassis_id = neighbor_data["id"]["value"]
                                    .as_str()
                                    .unwrap_or("unknown")
                                    .to_string();
                                let description =
                                    neighbor_data["descr"].as_str().unwrap_or("").to_string();

                                // Find the interface this neighbor is connected to
                                if let Some(interface_id) = self.interface_by_name(interface_name)
                                    && let Some(interface) = self
                                        .interfaces
                                        .iter_mut()
                                        .find(|i| i.interface_id == interface_id)
                                {
                                    let neighbor_info = format!(
                                        "LLDP: {} ({}), MAC: {}, Desc: {}",
                                        neighbor_name,
                                        mgmt_ip,
                                        chassis_id,
                                        description.chars().take(100).collect::<String>()
                                    );

                                    interface
                                        .neighbour_string_data
                                        .insert(neighbor_name.to_string(), neighbor_info);
                                    neighbor_count += 1;

                                    info!(
                                        "Added LLDP neighbor {} to interface {}",
                                        neighbor_name, interface_name
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        info!("Parsed {} LLDP neighbors", neighbor_count);
        Ok(neighbor_count)
    }

    fn parse_identity(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        debug!("Parsing identity from input: {}", input_data);
        self.system_identity = Some(input_data.trim().to_string());
        Ok(())
    }

    fn parse_ip_addresses(&mut self, _input_data: &str) -> Result<(), TrailFinderError> {
        debug!("parse_ip_addresses Covered by parse_interfaces");
        Ok(())
    }

    fn parse_ipsec(&mut self, _input_data: &str) -> Result<(), TrailFinderError> {
        debug!("Not supported on Ubiquiti devices (yet?)");
        Ok(())
    }

    fn build(self) -> Device {
        Device {
            device_id: uuid::Uuid::new_v4(),
            hostname: self.hostname,
            name: self.name,
            owner: self.owner,
            device_type: self.device_type,
            routes: self.routes,
            interfaces: self.interfaces,
            system_identity: self.system_identity,
            ipsec_peers: self.ipsec_peers,
        }
    }

    fn interface_by_name(&self, name: &str) -> Option<uuid::Uuid> {
        self.interfaces
            .iter()
            .find(|iface| iface.name == name)
            .map(|iface| iface.interface_id)
    }

    fn get_interfaces_command(&self) -> String {
        "ip address show".to_string()
    }

    fn get_routes_command(&self) -> String {
        "ip route show".to_string()
    }

    fn get_cdp_command(&self) -> String {
        "lldpcli -f json show neighbors".to_string()
    }

    #[allow(clippy::manual_async_fn)]
    fn interrogate_device(
        &self,
        ssh_client: &mut crate::ssh::SshClient,
        _device_config: &crate::config::DeviceConfig,
        device_type: DeviceType,
    ) -> impl std::future::Future<Output = Result<crate::config::DeviceState, TrailFinderError>> + Send
    {
        async move {
            let mut interrogator = Ubiquiti::new(
                self.hostname.clone(),
                self.name.clone(),
                self.owner.clone(),
                device_type,
            );

            let board_info_output = ssh_client.execute_command(GET_BOARD_INFO).await?;
            debug!("Board Info Output: {}", board_info_output);

            if let Some(line) = board_info_output
                .lines()
                .find(|line| line.starts_with("board.name"))
            {
                let parts: Vec<&str> = line.split('=').collect();
                if parts.len() == 2 {
                    let board_name = parts[1].trim_matches('"').to_string();
                    debug!("Detected Board Name: {}", board_name);

                    if board_name.to_lowercase().contains("ap") {
                        interrogator.device_type = DeviceType::AccessPoint;
                    } else {
                        debug!("Couldn't identify device based on board name, defaulting to Router")
                    }
                }
            }

            let hostname_output = ssh_client
                .execute_command(Self::GET_IDENTITY_COMMAND)
                .await?;
            interrogator.parse_identity(&hostname_output)?;

            let interfaces_output = ssh_client
                .execute_command(&self.get_interfaces_command())
                .await?;
            interrogator.parse_interfaces(&interfaces_output)?;

            let routes_output = ssh_client
                .execute_command(&self.get_routes_command())
                .await?;
            interrogator.parse_routes(&routes_output)?;

            let neighbors_output = ssh_client.execute_command(&self.get_cdp_command()).await?;
            let known_devices = vec![]; // You might want to pass known devices here
            interrogator.parse_neighbours(&neighbors_output, known_devices)?;

            // let system_info_output = ssh_client.execute_command(GET_SYSTEM_INFO_COMMAND).await?;
            // // You can parse system info if needed

            // let model_info_output = ssh_client.execute_command(GET_MODEL_INFO_COMMAND).await?;
            // // You can parse model info if needed

            let ipsec_output = ssh_client
                .execute_command(Ubiquiti::GET_IPSEC_COMMAND)
                .await?;
            interrogator.parse_ipsec(&ipsec_output)?;

            Ok(crate::config::DeviceState::new(interrogator.build(), ""))
        }
    }
}

#[cfg(test)]
mod tests {

    use std::fs::read_to_string;

    use crate::setup_test_logging;

    use super::*;

    #[tokio::test]
    async fn test_parse_interfaces() {
        setup_test_logging();
        let test_data = read_to_string("src/tests/ubiquiti_ap_interfaces.txt")
            .expect("Failed to read test data file");
        let mut ubiquiti = Ubiquiti::default();
        ubiquiti
            .parse_interfaces(&test_data)
            .expect("Failed to parse interfaces");
    }

    #[tokio::test]
    async fn test_parse_routes() {
        setup_test_logging();
        let test_data = read_to_string("src/tests/ubiquiti_ap_routes.txt")
            .expect("Failed to read test data file");
        let mut ubiquiti = Ubiquiti::default();

        ubiquiti.interfaces.push(Interface {
            interface_id: uuid::Uuid::new_v4(),
            name: "br0".to_string(),
            interface_type: InterfaceType::Bridge,
            mac_address: None,
            vlans: Default::default(),
            addresses: Default::default(),
            comment: Default::default(),
            neighbour_string_data: Default::default(),
            peers: Default::default(),
        });

        ubiquiti
            .parse_routes(&test_data)
            .expect("Failed to parse routes");

        assert_eq!(ubiquiti.routes.len(), 1);
        if let RouteType::Default(_) = ubiquiti.routes[0].route_type {
            // Correct route type
        } else {
            panic!("Expected default route");
        }
    }

    #[tokio::test]
    async fn test_parse_neighbors() {
        setup_test_logging();
        let test_data = read_to_string("src/tests/ubiquiti_ap_lldp.txt")
            .expect("Failed to read test data file");
        let mut ubiquiti = Ubiquiti::default();

        // Add eth0 interface that appears in LLDP data
        ubiquiti.interfaces.push(Interface {
            interface_id: uuid::Uuid::new_v4(),
            name: "eth0".to_string(),
            interface_type: InterfaceType::Ethernet,
            mac_address: Some("b4:fb:e4:49:bf:0f".parse().unwrap()),
            vlans: Default::default(),
            addresses: Default::default(),
            comment: Default::default(),
            neighbour_string_data: Default::default(),
            peers: Default::default(),
        });

        let neighbor_count = ubiquiti
            .parse_neighbours(&test_data, vec![])
            .expect("Failed to parse neighbors");

        assert_eq!(neighbor_count, 1);
        assert_eq!(ubiquiti.interfaces[0].neighbour_string_data.len(), 1);
        assert!(
            ubiquiti.interfaces[0]
                .neighbour_string_data
                .values()
                .any(|v| v.contains("C3650.example.com"))
        );
    }

    #[tokio::test]
    async fn test_parse_identity() {
        setup_test_logging();
        let mut ubiquiti = Ubiquiti::default();

        ubiquiti
            .parse_identity("unifi-ap-hostname\n")
            .expect("Failed to parse identity");
        assert_eq!(
            ubiquiti.system_identity,
            Some("unifi-ap-hostname".to_string())
        );
    }

    #[tokio::test]
    async fn test_interface_classification() {
        setup_test_logging();
        let test_data = read_to_string("src/tests/ubiquiti_ap_interfaces.txt")
            .expect("Failed to read test data file");
        let mut ubiquiti = Ubiquiti::default();

        ubiquiti
            .parse_interfaces(&test_data)
            .expect("Failed to parse interfaces");

        // Check that we have the expected interfaces
        assert!(!ubiquiti.interfaces.is_empty());

        // Verify interface types are correctly classified
        let lo_interface = ubiquiti.interfaces.iter().find(|i| i.name == "lo");
        assert!(lo_interface.is_some());
        assert_eq!(
            lo_interface.unwrap().interface_type,
            InterfaceType::Loopback
        );

        let ath_interface = ubiquiti.interfaces.iter().find(|i| i.name == "ath0");
        assert!(ath_interface.is_some());
        if let InterfaceType::Other(ref itype) = ath_interface.unwrap().interface_type {
            assert_eq!(itype, "wireless");
        } else {
            panic!("Expected wireless interface type");
        }

        let br_interface = ubiquiti.interfaces.iter().find(|i| i.name == "br0");
        assert!(br_interface.is_some());
        assert_eq!(br_interface.unwrap().interface_type, InterfaceType::Bridge);

        let vlan_interface = ubiquiti.interfaces.iter().find(|i| i.name == "eth0.20");
        assert!(vlan_interface.is_some());
        assert_eq!(vlan_interface.unwrap().interface_type, InterfaceType::Vlan);
    }

    #[tokio::test]
    async fn test_interface_addresses() {
        setup_test_logging();
        let test_data = read_to_string("src/tests/ubiquiti_ap_interfaces.txt")
            .expect("Failed to read test data file");
        let mut ubiquiti = Ubiquiti::default();

        ubiquiti
            .parse_interfaces(&test_data)
            .expect("Failed to parse interfaces");

        // Check that br0 interface has IP address
        let br0_interface = ubiquiti.interfaces.iter().find(|i| i.name == "br0");
        assert!(br0_interface.is_some());
        let br0 = br0_interface.unwrap();
        assert!(!br0.addresses.is_empty());
        assert!(
            br0.addresses
                .iter()
                .any(|addr| addr.to_string().starts_with("10.0.0.101"))
        );
    }

    #[tokio::test]
    async fn test_device_build() {
        setup_test_logging();
        let ubiquiti = Ubiquiti::new(
            "test-host".to_string(),
            Some("Test Device".to_string()),
            Owner::Named("Network".to_string()),
            DeviceType::AccessPoint,
        );

        let device = ubiquiti.build();
        assert_eq!(device.hostname, "test-host");
        assert_eq!(device.name, Some("Test Device".to_string()));
        assert_eq!(device.owner, Owner::Named("Network".to_string()));
        assert_eq!(device.device_type, DeviceType::AccessPoint);
    }
}
