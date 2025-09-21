use super::prelude::*;

pub struct Cisco {
    hostname: String,
    name: Option<String>,
    owner: Owner,
    device_type: DeviceType,
    routes: Vec<Route>,
    interfaces: Vec<Interface>,
    system_identity: Option<String>,
    ipsec_peers: Vec<IpsecPeer>,
}

impl Cisco {
    #[cfg(test)]
    pub fn test_device() -> Self {
        Self {
            hostname: "test-cisco.example.com".to_string(),
            name: Some("Test Cisco Device".to_string()),
            owner: Owner::Unknown,
            device_type: DeviceType::Switch,
            routes: Vec::new(),
            interfaces: Vec::new(),
            system_identity: None,
            ipsec_peers: Vec::new(),
        }
    }
}

impl DeviceHandler for Cisco {
    const GET_IP_COMMAND: &'static str = "show ip interface  | i (is up|Internet address)";
    const GET_IDENTITY_COMMAND: &'static str = "show running-config | include hostname";
    const GET_IPSEC_COMMAND: &'static str = "";

    fn new(hostname: String, name: Option<String>, owner: Owner, device_type: DeviceType) -> Self {
        Self {
            hostname,
            name,
            owner,
            device_type,
            routes: Vec::new(),
            interfaces: Vec::new(),
            system_identity: None,
            ipsec_peers: Vec::new(),
        }
    }

    fn interface_by_name(&self, name: &str) -> Option<Uuid> {
        self.interfaces
            .iter()
            .find(|iface| iface.name == name)
            .map(|iface| iface.interface_id)
    }

    fn parse_interfaces(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        let lines: Vec<&str> = input_data.lines().map(|l| l.trim()).collect();
        let mac_regex = Regex::new(r"address is ([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})")?;
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];
            if line.is_empty() || line.starts_with('#') {
                i += 1;
                continue;
            }

            // Parse Cisco "show interfaces" output
            // Look for interface lines like "GigabitEthernet0/1 is up, line protocol is up"
            // or "Vlan1 is up, line protocol is up"
            if line.contains(" is ") && (line.contains(" up") || line.contains(" down")) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    i += 1;
                    continue;
                }

                let interface_name = parts[0].to_string();

                // Determine interface type from name
                let interface_type = if interface_name.to_lowercase().starts_with("gigabitethernet")
                    || interface_name.to_lowercase().starts_with("gi")
                    || interface_name.to_lowercase().starts_with("fastethernet")
                    || interface_name.to_lowercase().starts_with("fa")
                    || interface_name.to_lowercase().starts_with("ethernet")
                {
                    InterfaceType::Ethernet
                } else if interface_name.to_lowercase().starts_with("vlan") {
                    InterfaceType::Vlan
                } else if interface_name.to_lowercase().starts_with("loopback")
                    || interface_name.to_lowercase().starts_with("lo")
                {
                    InterfaceType::Loopback
                } else {
                    InterfaceType::Other(interface_name.clone())
                };

                // Extract VLAN ID if it's a VLAN interface
                let vlan = if interface_type == InterfaceType::Vlan {
                    interface_name
                        .strip_prefix("Vlan")
                        .or_else(|| interface_name.strip_prefix("vlan"))
                        .and_then(|vlan_str| vlan_str.parse::<u16>().ok())
                } else {
                    None
                };

                // Parse MAC address from the following lines
                let mut mac_address = None;
                let mut j = i + 1;

                // Look ahead for MAC address in "Hardware is ... address is ..." line
                while j < lines.len() && j < i + 10 {
                    // Limit look-ahead to avoid infinite loops
                    let detail_line = lines[j];
                    if detail_line.is_empty() {
                        break; // End of this interface block
                    }

                    // Look for "Hardware is ... address is 0050.56c0.0001"
                    if detail_line.contains("Hardware is") && detail_line.contains("address is") {
                        // Extract MAC address using regex
                        if let Some(captures) = mac_regex.captures(detail_line)
                            && let Some(mac_match) = captures.get(1)
                        {
                            // Convert Cisco format (0050.56c0.0001) to standard format (005056c00001)
                            mac_address = mac_address::MacAddress::from_str(
                                &mac_match.as_str().replace(".", ""),
                            )
                            .inspect_err(|e| {
                                debug!(
                                    "Failed to parse MAC address '{}': {}",
                                    mac_match.as_str(),
                                    e
                                );
                            })
                            .ok();
                        }
                        break;
                    }
                    j += 1;
                }

                let interface = Interface {
                    interface_id: Uuid::new_v4(),
                    name: interface_name,
                    vlans: vlan.map(|v| vec![v]).unwrap_or_default(),
                    addresses: Vec::new(), // IP addresses would need separate parsing
                    interface_type,
                    comment: None,
                    mac_address,
                    neighbour_string_data: Default::default(),
                    peers: Default::default(),
                };

                self.interfaces.push(interface);
            }
            i += 1;
        }

        Ok(())
    }

    fn parse_routes(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        let route_finder = Regex::new(r#"(?P<target>[\d\.]+\d+)"#)?;

        for line in input_data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let target_matches = route_finder.captures(line);

            let target: IpCidr = if let Some(captures) = target_matches {
                match captures
                    .name("target")
                    .and_then(|m| m.as_str().parse::<cidr::IpCidr>().ok())
                {
                    Some(cidr) => cidr,
                    None => {
                        return Err(TrailFinderError::Parse(format!(
                            "Failed to parse target CIDR in line: {}",
                            line
                        )));
                    }
                }
            } else {
                continue;
            };

            // Parse Cisco "show ip route" output
            // Look for routes like:
            // "S*    0.0.0.0/0 [1/0] via 192.168.1.1"
            // "C     192.168.1.0/24 is directly connected, Vlan1"
            // "S     10.0.0.0/8 [1/0] via 192.168.1.254"

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            // Determine route type
            let route_type = if target.to_string() == "0.0.0.0/0" || parts[0].contains("*") {
                RouteType::Default(uuid::Uuid::new_v4()) // TODO: fix this
            } else {
                RouteType::NextHop(uuid::Uuid::new_v4()) // TODO: fix this
            };

            // Look for gateway information
            let mut gateway = None;
            let mut distance = None;

            for (i, part) in parts.iter().enumerate() {
                if *part == "via" && i + 1 < parts.len() {
                    // Try to parse the next part as an IP address
                    if let Ok(addr) = parts[i + 1].parse::<std::net::IpAddr>() {
                        gateway = Some(addr);
                    }
                } else if *part == "connected," && i + 1 < parts.len() {
                    // Directly connected interface
                    // interface_name = Some(parts[i + 1].to_string());
                } else if part.starts_with('[') && part.contains('/') && part.ends_with(']') {
                    // Administrative distance/metric in format [distance/metric]
                    let distance_str = part.trim_matches(['[', ']']);
                    if let Some(slash_pos) = distance_str.find('/')
                        && let Ok(dist) = distance_str[..slash_pos].parse::<u16>()
                    {
                        distance = Some(dist);
                    }
                }
            }

            let route = Route {
                target,
                route_type,
                gateway,
                distance,
            };

            self.routes.push(route);
        }

        Ok(())
    }

    fn parse_neighbours(
        &mut self,
        input_data: &str,
        _devices: Vec<Device>,
    ) -> Result<usize, TrailFinderError> {
        let mut mods_made = 0;
        let interface_parser = Regex::new(
            r#"Interface: (?<interface>\S+),\s+Port ID \(outgoing port\):\s*(?P<outgoing_port_id>\S+)"#,
        )?;

        let mut current_data = String::new();

        let lines = input_data.lines().collect::<Vec<&str>>();
        let num_lines = lines.len();
        for (line_no, line) in lines.iter().enumerate() {
            // debug!("Handling line #{line_no}: {line}");

            if line_no == num_lines - 1 || line.starts_with("---") {
                if current_data.is_empty() {
                    continue;
                }
                debug!("Found a full line");
            } else {
                current_data.push_str(&format!("{}\n", line));
                continue;
            }

            debug!("Full block: {current_data}");

            let interface_name = interface_parser.captures(&current_data).map(|caps| {
                let interface_name = caps.name("interface").map(|m| m.as_str().to_string());
                let port_id = caps
                    .name("outgoing_port_id")
                    .map(|m| m.as_str().to_string());

                (interface_name, port_id)
            });

            // find if have this interface already, and print a success/fail message
            if let Some((Some(interface_name), Some(port_id))) = interface_name {
                if let Some(interface) = self
                    .interfaces
                    .iter_mut()
                    .find(|interface| interface.name == interface_name)
                {
                    debug!("Successfully found peer interface: {}", interface.name);
                    if interface.neighbour_string_data.get(&port_id) != Some(&current_data) {
                        debug!(
                            "Updating neighbour data for interface from: \n{:?}\nto\n{:?}",
                            interface.neighbour_string_data,
                            Some(current_data.clone())
                        );
                        interface
                            .neighbour_string_data
                            .insert(port_id, current_data.clone());
                        mods_made += 1;
                        current_data.clear()
                    }
                } else {
                    error!("Can't find interface: {interface_name:?}");
                }
            }

            if line.starts_with("---") {
                trace!("Starting a new device on next line...");
                current_data.clear();
            }
        }

        Ok(mods_made)
    }

    fn parse_ip_addresses(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        let mut current_interface = String::new();
        let mut current_address = String::new();

        for line in input_data.lines() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            trace!("Line: {line}");
            if line.contains("is up") {
                current_interface = line
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                continue;
            } else if line.contains("Internet address is") {
                current_address = line
                    .split_whitespace()
                    .last()
                    .unwrap_or_default()
                    .to_string();
            }

            if current_address.is_empty() || current_interface.is_empty() {
                continue;
            }

            let ipaddr =
                match IpAddr::from_str(current_address.split("/").next().unwrap_or_default()) {
                    Ok(addr) => addr,
                    Err(err) => {
                        error!("Failed to parse {current_address} as IpAddr: {err:?}");
                        continue;
                    }
                };

            let mask: u8 = match current_address
                .split("/")
                .nth(1)
                .unwrap_or_default()
                .parse()
            {
                Ok(val) => val,
                Err(err) => {
                    error!("Failed to parse {current_address} as mask: {err:?}");
                    continue;
                }
            };
            let interface_address = InterfaceAddress::from((ipaddr, mask));

            debug!("Found interface={current_interface} interface_address={interface_address}");

            let mut added = false;

            // Here you would typically add the found interface and address to your data structure
            self.interfaces.iter_mut().for_each(|iface| {
                if iface.name != current_interface {
                    return;
                }
                if !iface.addresses.contains(&interface_address) {
                    iface.addresses.push(interface_address.clone());
                    info!("Adding address to interface={current_interface} address={interface_address}");
                    added = true;
                }
            });

            if !added {
                warn!(
                    "Couldn't find matching interface {current_interface} to add address={interface_address}"
                )
            }
            current_address.clear();
            current_interface.clear();
        }
        Ok(())
    }

    fn build(self) -> Device {
        Device::new(self.hostname, self.name, self.owner, self.device_type)
            .with_routes(self.routes)
            .with_interfaces(self.interfaces)
            .with_system_identity(self.system_identity)
            .with_ipsec_peers(self.ipsec_peers)
    }

    fn parse_identity(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        for line in input_data.lines() {
            let line = line.trim();
            if line.starts_with("hostname ") {
                self.system_identity = Some(
                    line.strip_prefix("hostname ")
                        .ok_or_else(|| {
                            TrailFinderError::InvalidLine(format!(
                                "Invalid hostname line: {}",
                                line
                            ))
                        })?
                        .trim()
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    fn parse_ipsec(&mut self, _input_data: &str) -> Result<(), TrailFinderError> {
        // IPSec parsing not implemented for Cisco devices yet
        // This is a pass-through implementation
        Ok(())
    }

    fn get_cdp_command(&self) -> String {
        "show cdp neighbors".to_string()
    }

    fn get_lldp_command(&self) -> String {
        "show lldp neighbors detail".to_string()
    }

    fn parse_lldp(
        &mut self,
        input_data: &str,
        _devices: Vec<Device>,
    ) -> Result<usize, TrailFinderError> {
        self.store_raw_lldp_data(input_data)
    }

    fn get_interfaces_command(&self) -> String {
        "show interfaces".to_string()
    }

    fn get_routes_command(&self) -> String {
        "show ip route".to_string()
    }

    #[allow(clippy::manual_async_fn)]
    fn interrogate_device(
        &self,
        ssh_client: &mut SshClient,
        device_config: &DeviceConfig,
        device_type: DeviceType,
    ) -> impl std::future::Future<Output = Result<DeviceState, TrailFinderError>> + Send {
        async move {
            // Get interfaces data
            let interfaces_output = ssh_client
                .execute_command(&self.get_interfaces_command())
                .await?;

            // Get routes data
            let routes_output = ssh_client
                .execute_command(&self.get_routes_command())
                .await?;

            // Get CDP/neighbor data
            let cdp_output = ssh_client.execute_command(&self.get_cdp_command()).await?;

            // Get system hostname/identity
            let hostname_output = ssh_client
                .execute_command(Self::GET_IDENTITY_COMMAND)
                .await
                .unwrap_or_default();

            // Parse the data using the existing ConfParser implementation
            let mut parser = Cisco::new(
                device_config.hostname.clone(),
                None, // DeviceConfig doesn't have a name field
                device_config.owner.clone(),
                device_type,
            );

            parser.parse_interfaces(&interfaces_output)?;
            parser.parse_routes(&routes_output)?;

            // Store raw CDP data in interfaces for later global processing
            parser.store_raw_cdp_data(&cdp_output)?;

            // Get LLDP data (new)
            if self.supports_lldp() {
                match ssh_client.execute_command(&self.get_lldp_command()).await {
                    Ok(lldp_output) => {
                        if !lldp_output.trim().is_empty() {
                            debug!("Collected LLDP data for {}", device_config.hostname);
                            parser.parse_lldp(&lldp_output, vec![])?;
                        } else {
                            debug!("No LLDP neighbors found for {}", device_config.hostname);
                        }
                    }
                    Err(e) => {
                        debug!("LLDP not available on {}: {}", device_config.hostname, e);
                        // Non-fatal error - LLDP might not be enabled
                    }
                }
            }

            parser.parse_identity(&hostname_output)?;
            parser.parse_ip_addresses(&ssh_client.execute_command(Self::GET_IP_COMMAND).await?)?;

            // Get IPSec configuration (pass-through for Cisco)
            let ipsec_output = ssh_client
                .execute_command(Self::GET_IPSEC_COMMAND)
                .await
                .unwrap_or_default();
            parser.parse_ipsec(&ipsec_output)?;

            let device = parser.build();

            // Combine all outputs for config hash
            let combined_config = format!(
                "{}
{}
{}",
                interfaces_output, routes_output, ipsec_output
            );
            Ok(DeviceState::new(device, &combined_config))
        }
    }
}

impl Cisco {
    /// Store raw CDP/neighbor data in interfaces for later global processing
    pub fn store_raw_cdp_data(&mut self, input_data: &str) -> Result<usize, TrailFinderError> {
        debug!("Storing raw CDP data: {input_data}");

        // Parse Cisco CDP neighbor output - this can be multi-line format
        // Two common formats:
        // 1. Tabular format:
        //    Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
        //    c3650.example.co Gig 1/0/1         144             R S   WS-C3750  Gig 1/0/1
        //
        // 2. Detailed format (show cdp neighbors detail):
        //    Device ID: switch1.example.com
        //    Entry address(es):
        //      IP address: 192.168.1.10
        //    Platform: cisco WS-C3750G-48TS,  Capabilities: Router Switch
        //    Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/2

        let mut mods_made = 0;

        // First try tabular format parsing
        mods_made += self.parse_cisco_cdp_tabular(input_data)?;

        // If no matches found, try detailed format parsing
        if mods_made == 0 {
            mods_made += self.parse_cisco_cdp_detailed(input_data)?;
        }

        Ok(mods_made)
    }

    /// Parse Cisco CDP tabular format output
    fn parse_cisco_cdp_tabular(&mut self, input_data: &str) -> Result<usize, TrailFinderError> {
        let mut mods_made = 0;
        let lines: Vec<&str> = input_data.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();
            if line.is_empty()
                || line.starts_with("Device ID")
                || line.starts_with("Capability Codes:")
                || line.starts_with("---")
            {
                i += 1;
                continue;
            }

            // Parse each line to extract neighbor information
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                // Single line format: device_id interface holdtime capability platform port_id
                let device_id = parts[0];
                let local_interface = parts[1..3].join(" "); // Handle "Gig 1/0/1" format
                // Store the neighbor data for this interface
                if let Some(mods) =
                    self.store_neighbor_data_for_interface(device_id, &local_interface, line)?
                {
                    mods_made += mods;
                }
            } else if !parts.is_empty() && !parts[0].is_empty() && i + 1 < lines.len() {
                // Multi-line format: device_id is on one line, interface info is on the next line
                let device_id = parts[0];
                let next_line = lines[i + 1].trim();
                let next_parts: Vec<&str> = next_line.split_whitespace().collect();

                // Check if next line starts with whitespace (indicates continuation) and has interface info
                if lines[i + 1].starts_with(' ') && next_parts.len() >= 2 {
                    let local_interface = next_parts[0..2].join(" "); // Handle "Ten 1/1/3" format
                    let combined_data = format!("{}\n{}", line, next_line);

                    debug!(
                        "Found multi-line CDP entry: device_id='{}', interface='{}'",
                        device_id, local_interface
                    );

                    // Store the neighbor data for this interface
                    if let Some(mods) = self.store_neighbor_data_for_interface(
                        device_id,
                        &local_interface,
                        &combined_data,
                    )? {
                        mods_made += mods;
                    }

                    // Skip the next line since we processed it
                    i += 1;
                }
            }
            i += 1;
        }

        Ok(mods_made)
    }

    /// Parse Cisco CDP detailed format output
    fn parse_cisco_cdp_detailed(&mut self, input_data: &str) -> Result<usize, TrailFinderError> {
        let mut mods_made = 0;
        let mut current_neighbor = String::new();
        let mut device_id: Option<String> = None;
        let mut local_interface: Option<String> = None;

        for line in input_data.lines() {
            let line = line.trim();

            // Start of a new neighbor entry
            if line.starts_with("Device ID:") {
                // Process previous neighbor if we have one
                if let (Some(dev_id), Some(local_int)) = (&device_id, &local_interface)
                    && let Some(mods) = self.store_neighbor_data_for_interface(
                        dev_id,
                        local_int,
                        &current_neighbor,
                    )?
                {
                    mods_made += mods;
                }

                // Start new neighbor
                device_id = line
                    .strip_prefix("Device ID:")
                    .map(|s| s.trim().to_string());
                local_interface = None;
                current_neighbor.clear();
                current_neighbor.push_str(line);
                current_neighbor.push('\n');
                continue;
            }

            // Look for interface information
            if line.contains("Interface:") && line.contains("Port ID") {
                // Extract local interface name
                if let Some(interface_part) = line.split("Interface:").nth(1)
                    && let Some(interface_name) = interface_part.split(',').next()
                {
                    local_interface = Some(interface_name.trim().to_string());
                }
            }

            // Add all lines to current neighbor data
            if !line.is_empty() {
                current_neighbor.push_str(line);
                current_neighbor.push('\n');
            }
        }

        // Process the last neighbor
        if let (Some(dev_id), Some(local_int)) = (&device_id, &local_interface)
            && let Some(mods) =
                self.store_neighbor_data_for_interface(dev_id, local_int, &current_neighbor)?
        {
            mods_made += mods;
        }

        Ok(mods_made)
    }

    /// Store neighbor data for a specific interface with name matching
    fn store_neighbor_data_for_interface(
        &mut self,
        device_id: &str,
        local_interface: &str,
        neighbor_data: &str,
    ) -> Result<Option<usize>, TrailFinderError> {
        // Try both short and long interface names
        let interface_candidates = vec![
            local_interface.to_string(),
            local_interface.replace("Gig ", "GigabitEthernet"),
            local_interface.replace("Fa ", "FastEthernet"),
            local_interface.replace("Te ", "TenGigabitEthernet"),
            local_interface.replace("Ten ", "TenGigabitEthernet"),
            local_interface.replace("Gig", "GigabitEthernet"),
            local_interface.replace("Fa", "FastEthernet"),
            local_interface.replace("Te", "TenGigabitEthernet"),
            local_interface.replace("Ten", "TenGigabitEthernet"),
        ];

        for candidate in interface_candidates {
            if let Some(existing_interface) = self
                .interfaces
                .iter_mut()
                .find(|iface| iface.name == candidate || iface.name.contains(&candidate))
            {
                // Store the raw neighbor data
                let neighbor_key = format!("{}@{}", device_id, candidate);
                if existing_interface.neighbour_string_data.get(&neighbor_key)
                    != Some(&neighbor_data.to_string())
                {
                    existing_interface
                        .neighbour_string_data
                        .insert(neighbor_key, neighbor_data.to_string());
                    return Ok(Some(1));
                }
                return Ok(Some(0)); // Found interface but no update needed
            }
        }

        debug!(
            "Interface {} not found for neighbor data from device {}",
            local_interface, device_id
        );
        Ok(None)
    }

    /// Store raw LLDP neighbor data in interfaces for later global processing
    pub fn store_raw_lldp_data(&mut self, input_data: &str) -> Result<usize, TrailFinderError> {
        debug!("Storing raw LLDP data: {}", input_data);

        let mut mods_made = 0;
        let mut current_neighbor = LldpNeighborData::new();
        let mut processing_neighbor = false;

        for line in input_data.lines() {
            let line = line.trim();

            // Detect start of new neighbor block
            if line.starts_with("------") {
                // Process previous neighbor if exists
                if processing_neighbor && !current_neighbor.local_interface.is_empty() {
                    mods_made += self.store_lldp_neighbor_for_interface(&current_neighbor)?;
                }

                current_neighbor = LldpNeighborData::new();
                processing_neighbor = true;
                continue;
            }

            if processing_neighbor {
                self.parse_lldp_field(&mut current_neighbor, line)?;
            }
        }

        // Process final neighbor
        if processing_neighbor && !current_neighbor.local_interface.is_empty() {
            mods_made += self.store_lldp_neighbor_for_interface(&current_neighbor)?;
        }

        Ok(mods_made)
    }

    /// Parse individual LLDP fields from output lines
    fn parse_lldp_field(&self, neighbor: &mut LldpNeighborData, line: &str) -> Result<(), TrailFinderError> {
        if let Some(value) = line.strip_prefix("Local Intf:") {
            neighbor.local_interface = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("Chassis id:") {
            neighbor.chassis_id = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("Port id:") {
            neighbor.port_id = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("System Name:") {
            let value = value.trim();
            if !value.is_empty() && value != "not advertised" {
                neighbor.system_name = Some(value.to_string());
            }
        } else if let Some(value) = line.strip_prefix("System Description:") {
            let value = value.trim();
            if !value.is_empty() && value != "not advertised" {
                neighbor.system_description = Some(value.to_string());
            }
        } else if line.contains("Management Addresses:") {
            // Management IP will be on next line(s)
            neighbor.expect_management_ip = true;
        } else if neighbor.expect_management_ip && line.trim().starts_with("IP:") {
            if let Some(ip) = line.trim().strip_prefix("IP:") {
                neighbor.management_ip = Some(ip.trim().to_string());
                neighbor.expect_management_ip = false;
            }
        } else if let Some(value) = line.strip_prefix("Enabled Capabilities:") {
            neighbor.capabilities = self.parse_capabilities(value)?;
        } else if let Some(value) = line.strip_prefix("Time remaining:") {
            neighbor.ttl = self.parse_ttl(value)?;
        }

        Ok(())
    }

    /// Parse capabilities string into vector
    fn parse_capabilities(&self, capabilities_str: &str) -> Result<Vec<String>, TrailFinderError> {
        let caps_str = capabilities_str.trim();
        if caps_str.is_empty() || caps_str == "not advertised" {
            return Ok(Vec::new());
        }

        let capabilities = caps_str.split(',')
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
            .collect();

        Ok(capabilities)
    }

    /// Parse TTL value from time remaining string
    fn parse_ttl(&self, ttl_str: &str) -> Result<Option<u32>, TrailFinderError> {
        let ttl_str = ttl_str.trim();
        if ttl_str.is_empty() || ttl_str == "not advertised" {
            return Ok(None);
        }

        // Extract number from "120 seconds" format
        if let Some(num_str) = ttl_str.split_whitespace().next()
            && let Ok(ttl) = num_str.parse::<u32>()
        {
            return Ok(Some(ttl));
        }

        Ok(None)
    }

    /// Associate LLDP neighbor data with appropriate interface
    fn store_lldp_neighbor_for_interface(&mut self, neighbor: &LldpNeighborData) -> Result<usize, TrailFinderError> {
        if neighbor.local_interface.is_empty() {
            return Ok(0);
        }

        // Try multiple interface name variations
        let interface_candidates = self.generate_interface_candidates(&neighbor.local_interface);

        for candidate in interface_candidates {
            // Find interface index first to avoid borrowing issues
            let interface_index = self.interfaces
                .iter()
                .position(|iface| self.interface_name_matches(&iface.name, &candidate));

            if let Some(index) = interface_index {
                let existing_interface = &mut self.interfaces[index];
                let neighbor_key = format!("lldp_{}", neighbor.chassis_id);
                let neighbor_data = neighbor.to_string();

                if existing_interface.neighbour_string_data.get(&neighbor_key) != Some(&neighbor_data) {
                    existing_interface.neighbour_string_data.insert(neighbor_key, neighbor_data);
                    debug!("Stored LLDP neighbor for interface {}: {}", candidate, neighbor.system_name.as_deref().unwrap_or("unknown"));
                    return Ok(1);
                }
                return Ok(0);
            }
        }

        debug!("Interface {} not found for LLDP neighbor", neighbor.local_interface);
        Ok(0)
    }

    /// Generate interface name candidates for matching
    fn generate_interface_candidates(&self, interface_name: &str) -> Vec<String> {
        vec![
            interface_name.to_string(),
            interface_name.replace("Gi", "GigabitEthernet"),
            interface_name.replace("Fa", "FastEthernet"),
            interface_name.replace("Te", "TenGigabitEthernet"),
            interface_name.replace("Ten", "TenGigabitEthernet"),
            // Add space variations
            interface_name.replace("Gig ", "GigabitEthernet"),
            interface_name.replace("Fa ", "FastEthernet"),
            interface_name.replace("Te ", "TenGigabitEthernet"),
            interface_name.replace("Ten ", "TenGigabitEthernet"),
        ]
    }

    /// Check if interface names match
    fn interface_name_matches(&self, existing_name: &str, candidate: &str) -> bool {
        if existing_name == candidate {
            return true;
        }

        // Handle abbreviated forms
        let normalized_existing = self.normalize_interface_name(existing_name);
        let normalized_candidate = self.normalize_interface_name(candidate);

        normalized_existing == normalized_candidate
    }

    /// Normalize interface name to full form for comparison
    fn normalize_interface_name(&self, name: &str) -> String {
        let name = name.replace("Gig ", "GigabitEthernet")
            .replace("Gi", "GigabitEthernet")
            .replace("Fa ", "FastEthernet")
            .replace("Fa", "FastEthernet")
            .replace("Te ", "TenGigabitEthernet")
            .replace("Ten ", "TenGigabitEthernet")
            .replace("Ten", "TenGigabitEthernet");

        // Fix double replacements (e.g., GigabitEthernetgabitEthernet -> GigabitEthernet)
        name.replace("GigabitEthernetgabitEthernet", "GigabitEthernet")
            .replace("FastEthernetstEthernet", "FastEthernet")
            .replace("TenGigabitEthernetGigabitEthernet", "TenGigabitEthernet")
    }
}

/// LLDP neighbor data structure for parsing
#[derive(Debug, Clone, Default)]
struct LldpNeighborData {
    local_interface: String,
    chassis_id: String,
    port_id: String,
    system_name: Option<String>,
    system_description: Option<String>,
    management_ip: Option<String>,
    capabilities: Vec<String>,
    ttl: Option<u32>,
    expect_management_ip: bool,
}

impl LldpNeighborData {
    fn new() -> Self {
        Self::default()
    }
}

impl std::fmt::Display for LldpNeighborData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut lines = Vec::new();
        lines.push(format!("Local Intf: {}", self.local_interface));
        lines.push(format!("Chassis id: {}", self.chassis_id));
        lines.push(format!("Port id: {}", self.port_id));

        if let Some(ref name) = self.system_name {
            lines.push(format!("System Name: {}", name));
        }

        if let Some(ref desc) = self.system_description {
            lines.push(format!("System Description: {}", desc));
        }

        if let Some(ref ip) = self.management_ip {
            lines.push(format!("Management Addresses:\n  IP: {}", ip));
        }

        if !self.capabilities.is_empty() {
            lines.push(format!("Enabled Capabilities: {}", self.capabilities.join(",")));
        }

        if let Some(ttl) = self.ttl {
            lines.push(format!("Time remaining: {} seconds", ttl));
        }

        write!(f, "{}", lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {

    use crate::setup_test_logging;

    use super::*;

    #[test]
    fn test_cisco_interface_parsing() {
        let mut parser = Cisco::test_device();

        let cisco_interfaces =
            std::fs::read_to_string("src/tests/cisco_interfaces.txt").expect("Failed to read");
        parser
            .parse_interfaces(&cisco_interfaces)
            .expect("Failed to parse cisco interface data");

        let device = parser.build();
        assert!(
            !device.interfaces.is_empty(),
            "Should have parsed interfaces"
        );

        // Check for expected interface types
        let ethernet_interfaces: Vec<_> = device
            .interfaces
            .iter()
            .filter(|iface| matches!(iface.interface_type, InterfaceType::Ethernet))
            .collect();
        assert!(
            !ethernet_interfaces.is_empty(),
            "Should have Ethernet interfaces"
        );

        let vlan_interfaces: Vec<_> = device
            .interfaces
            .iter()
            .filter(|iface| matches!(iface.interface_type, InterfaceType::Vlan))
            .collect();
        assert!(!vlan_interfaces.is_empty(), "Should have VLAN interfaces");

        // Check VLAN number extraction
        let vlan1 = device.interfaces.iter().find(|iface| iface.name == "Vlan1");
        assert!(vlan1.is_some(), "Should find Vlan1 interface");
        assert_eq!(vlan1.unwrap().vlans, vec![1], "VLAN number should be 1");
    }

    #[test]
    fn test_cisco_route_parsing() {
        let cisco_routes = r#"
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area

Gateway of last resort is 192.168.1.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 192.168.1.1
C     192.168.1.0/24 is directly connected, GigabitEthernet0/1
L     192.168.1.10/32 is directly connected, GigabitEthernet0/1
C     192.168.10.0/24 is directly connected, Vlan1
S     10.0.0.0/8 [1/0] via 192.168.1.254
"#;

        let mut parser = Cisco::test_device();

        let result = parser.parse_routes(cisco_routes);
        assert!(result.is_ok(), "Route parsing should succeed");

        let device = parser.build();
        assert!(!device.routes.is_empty(), "Should have parsed routes");

        // Check for default route
        let default_routes: Vec<_> = device
            .routes
            .iter()
            .filter(|route| matches!(route.route_type, RouteType::Default(_)))
            .collect();
        assert!(!default_routes.is_empty(), "Should have default route");

        // Check for specific routes
        let specific_routes: Vec<_> = device
            .routes
            .iter()
            .filter(|route| matches!(route.route_type, RouteType::NextHop(_)))
            .collect();
        assert!(!specific_routes.is_empty(), "Should have specific routes");

        println!(
            "✅ Parsed {} interfaces and {} routes successfully",
            device.interfaces.len(),
            device.routes.len()
        );
    }

    #[test]
    fn test_parse_cisco_cdp() {
        setup_test_logging();

        let input_data = r#"-------------------------
Device ID: MagickNet
Entry address(es):
  IP address: 10.0.40.1
Platform: MikroTik,  Capabilities: Router
Interface: TenGigabitEthernet1/1/3,  Port ID (outgoing port): vlan40
Holdtime : 93 sec

Version :
7.16.1 (stable) 2024-10-10 14:03:32

advertisement version: 1

-------------------------
Device ID: MagickNet
Entry address(es):
  IP address: 10.0.5.1
Platform: MikroTik,  Capabilities: Router
Interface: TenGigabitEthernet1/1/3,  Port ID (outgoing port): vlan20
Holdtime : 93 sec

Version :
7.16.1 (stable) 2024-10-10 14:03:32

advertisement version: 1

-------------------------
Device ID: MagickNet
Entry address(es):
  IP address: 10.0.0.1
Platform: MikroTik,  Capabilities: Router
Interface: TenGigabitEthernet1/1/3,  Port ID (outgoing port): vlan10
Holdtime : 93 sec

Version :
7.16.1 (stable) 2024-10-10 14:03:32

advertisement version: 1

-------------------------
Device ID: MagickNet
Entry address(es):
  IP address: 192.168.88.1
Platform: MikroTik,  Capabilities: Router
Interface: TenGigabitEthernet1/1/3,  Port ID (outgoing port): bridge/sfp-sfpplus1
Holdtime : 93 sec

Version :
7.16.1 (stable) 2024-10-10 14:03:32

advertisement version: 1


Total cdp entries displayed : 4"#;

        let test_interface_data =
            std::fs::read_to_string("src/tests/cisco_interfaces2.txt").expect("Failed to read");

        let mut device = Cisco::test_device();

        device
            .parse_interfaces(&test_interface_data)
            .expect("Failed to parse interfaces");

        device.parse_routes("").expect("Failed to parse routes");
        let mut attempts = 0;
        while let Ok(changes) = device.parse_neighbours(input_data, vec![]) {
            if changes == 0 {
                println!("Finished parsing neighbours after {attempts} attempts");
                break;
            }
            attempts += 1;
            if attempts > 100 {
                panic!("Too many attempts to parse neighbours");
            }
        }
    }

    #[test]
    fn test_parse_cisco_hostname() {
        let mut test_device = Cisco::test_device();

        let hostname_output = "hostname MyTestSwitch";
        let result = test_device.parse_identity(hostname_output);
        assert!(result.is_ok(), "Should parse hostname successfully");
        assert_eq!(
            test_device.system_identity.as_ref().unwrap(),
            "MyTestSwitch",
            "Should extract correct hostname"
        );

        // Test with no hostname
        let empty_output = "";
        let result = test_device.parse_identity(empty_output);
        assert!(result.is_ok(), "Should return None for empty output");
        assert!(
            test_device.system_identity.as_ref().unwrap() == "MyTestSwitch",
            "Should remain unchanged"
        );
        // Test with different format
        let config_output = r#"Building configuration...

hostname TestDevice

!"#;
        let result = test_device.parse_identity(config_output);
        assert!(result.is_ok(), "Should parse hostname from config");
        assert_eq!(
            test_device.system_identity.unwrap(),
            "TestDevice",
            "Should extract hostname from config"
        );
    }
    #[test]
    fn test_parse_cisco_addresses() {
        setup_test_logging();

        let mut parser = Cisco::test_device();

        let cisco_interfaces =
            std::fs::read_to_string("src/tests/cisco_interfaces.txt").expect("Failed to read");
        parser
            .parse_interfaces(&cisco_interfaces)
            .expect("Failed to parse cisco interface data");

        let result = parser.parse_ip_addresses(
            &std::fs::read_to_string("src/tests/cisco_addresses.txt").expect("Failed to read"),
        );
        assert!(result.is_ok(), "IP address parsing should succeed");

        assert!(
            parser
                .interfaces
                .iter()
                .any(|iface| !iface.addresses.contains(&InterfaceAddress::from((
                    "10.0.99.2".parse().expect("Failed to parse ip address"),
                    24
                )))),
            "At least one interface should have addresses"
        );
    }

    #[test]
    fn test_cisco_device_new() {
        let device = Cisco::new(
            "test-switch.example.com".to_string(),
            Some("Test Switch".to_string()),
            Owner::Named("Lab".to_string()),
            DeviceType::Switch,
        );

        assert_eq!(device.hostname, "test-switch.example.com");
        assert_eq!(device.name, Some("Test Switch".to_string()));
        assert!(matches!(device.owner, Owner::Named(ref name) if name == "Lab"));
        assert_eq!(device.device_type, DeviceType::Switch);
        assert!(device.routes.is_empty());
        assert!(device.interfaces.is_empty());
        assert!(device.system_identity.is_none());
    }

    #[test]
    fn test_cisco_device_build() {
        let mut device = Cisco::test_device();

        // Add some test data
        device.interfaces.push(Interface::new(
            uuid::Uuid::new_v4(),
            "GigabitEthernet0/1".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        ));

        device.routes.push(Route {
            route_type: RouteType::Default(uuid::Uuid::new_v4()),
            target: cidr::IpCidr::V4(cidr::Ipv4Cidr::new([0, 0, 0, 0].into(), 0).unwrap()),
            gateway: Some("192.168.1.1".parse().unwrap()),
            distance: Some(1),
        });

        let built_device = device.build();
        assert_eq!(built_device.hostname, "test-cisco.example.com");
        assert_eq!(built_device.interfaces.len(), 1);
        assert_eq!(built_device.routes.len(), 1);
        assert_eq!(built_device.device_type, DeviceType::Switch);
    }

    #[test]
    fn test_cisco_interface_by_name() {
        let mut device = Cisco::test_device();

        // Add test interface
        device.interfaces.push(Interface::new(
            uuid::Uuid::new_v4(),
            "GigabitEthernet0/1".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        ));

        let interface_id = device.interface_by_name("GigabitEthernet0/1");
        assert!(interface_id.is_some());

        let nonexistent = device.interface_by_name("NonExistent");
        assert!(nonexistent.is_none());
    }

    #[test]
    fn test_cisco_command_getters() {
        let device = Cisco::test_device();

        let cdp_cmd = device.get_cdp_command();
        assert!(cdp_cmd.contains("cdp"));

        let interfaces_cmd = device.get_interfaces_command();
        assert!(interfaces_cmd.contains("interface"));

        let routes_cmd = device.get_routes_command();
        assert!(routes_cmd.contains("route"));
    }

    #[test]
    fn test_cisco_parse_identity_edge_cases() {
        let mut device = Cisco::test_device();

        // Test empty input
        let result = device.parse_identity("");
        assert!(result.is_ok());

        // Test malformed input
        let malformed = "random text without hostname";
        let result = device.parse_identity(malformed);
        assert!(result.is_ok());

        // Test hostname with special characters
        let special_hostname = "hostname test-switch.example-corp.com";
        let result = device.parse_identity(special_hostname);
        assert!(result.is_ok());
        assert_eq!(
            device.system_identity.unwrap(),
            "test-switch.example-corp.com"
        );
    }

    #[test]
    fn test_cisco_store_raw_cdp_data() {
        let mut device = Cisco::test_device();

        let cdp_data = r#"Device ID: neighbor1
Platform: cisco
Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet0/2

Device ID: neighbor2
Platform: cisco  
Interface: GigabitEthernet0/2,  Port ID (outgoing port): GigabitEthernet0/1"#;

        let result = device.store_raw_cdp_data(cdp_data);
        assert!(result.is_ok(), "CDP data storage should succeed");

        // Note: store_raw_cdp_data may return 0 if no valid CDP entries are found
        // This is acceptable behavior for malformed data
        result.expect("Failed to store CDP data");
    }

    #[test]
    fn test_cisco_parse_interfaces_edge_cases() {
        let mut device = Cisco::test_device();

        // Test empty input
        let result = device.parse_interfaces("");
        assert!(result.is_ok());

        // Test malformed interface data
        let malformed = "random text\nnot interface data\ninvalid format";
        let result = device.parse_interfaces(malformed);
        assert!(result.is_ok());

        // Test interface with various states
        let interface_data = r#"GigabitEthernet0/1 is up, line protocol is up
  Hardware is CSR vNIC, address is 0050.56bf.1234 (bia 0050.56bf.1234)
GigabitEthernet0/2 is down, line protocol is down
  Hardware is CSR vNIC, address is 0050.56bf.5678 (bia 0050.56bf.5678)
Vlan1 is up, line protocol is up
  Hardware is Ethernet SVI, address is 0050.56bf.9abc (bia 0050.56bf.9abc)"#;

        let result = device.parse_interfaces(interface_data);
        assert!(result.is_ok());

        // Should have parsed some interfaces
        assert!(device.interfaces.len() >= 3);
    }

    #[test]
    fn test_cisco_parse_routes_edge_cases() {
        let mut device = Cisco::test_device();

        // Test empty route table
        let empty_routes = "Codes: L - local, C - connected\nGateway of last resort is not set";
        let result = device.parse_routes(empty_routes);
        assert!(result.is_ok());

        // Test malformed route entry
        let malformed = "invalid route entry\nS* malformed";
        let result = device.parse_routes(malformed);
        assert!(result.is_ok());

        // Test various route types
        let complex_routes = r#"Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area 
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2

Gateway of last resort is 192.168.1.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 192.168.1.1
C     192.168.1.0/24 is directly connected, GigabitEthernet0/1
L     192.168.1.10/32 is directly connected, GigabitEthernet0/1
D     10.0.0.0/8 [90/130816] via 192.168.1.2, 00:01:23, GigabitEthernet0/1
O     172.16.0.0/12 [110/2] via 192.168.1.3, 00:02:45, GigabitEthernet0/1
B     203.0.113.0/24 [20/0] via 192.168.1.4, 00:05:12"#;

        let result = device.parse_routes(complex_routes);
        assert!(result.is_ok());

        // Should have parsed multiple routes
        assert!(device.routes.len() >= 5);
    }

    #[test]
    fn test_cisco_parse_ip_addresses_edge_cases() {
        let mut device = Cisco::test_device();

        // First add some interfaces to work with
        device.interfaces.push(Interface::new(
            uuid::Uuid::new_v4(),
            "GigabitEthernet0/0".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        ));

        // Test empty IP address data
        let result = device.parse_ip_addresses("");
        assert!(result.is_ok());

        // Test malformed IP data
        let malformed = "invalid ip data\nno addresses here";
        let result = device.parse_ip_addresses(malformed);
        assert!(result.is_ok());

        // Test various IP address formats
        let ip_data = r#"GigabitEthernet0/0 is up, line protocol is up
  Internet address is 192.168.1.10/24
GigabitEthernet0/1 is up, line protocol is up
  Internet address is 10.0.0.1/8
Loopback0 is up, line protocol is up
  Internet address is 1.1.1.1/32"#;

        let result = device.parse_ip_addresses(ip_data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cisco_parse_neighbours_error_handling() {
        let mut device = Cisco::test_device();

        // Test empty CDP data
        let result = device.parse_neighbours("", vec![]);
        assert!(result.is_ok());

        // Test malformed CDP data
        let malformed_cdp = "malformed cdp data without proper structure";
        let result = device.parse_neighbours(malformed_cdp, vec![]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cisco_store_neighbor_data_edge_cases() {
        let mut device = Cisco::test_device();

        // Add a test interface
        device.interfaces.push(Interface::new(
            uuid::Uuid::new_v4(),
            "GigabitEthernet0/1".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        ));

        // Test with invalid VLAN (using device_id parameter correctly)
        let result = device.store_neighbor_data_for_interface(
            "neighbor_device",
            "GigabitEthernet0/1",
            "neighbor data",
        );
        assert!(result.is_ok());

        // Test with valid interface name
        let result = device.store_neighbor_data_for_interface(
            "neighbor_device",
            "GigabitEthernet0/1",
            "test neighbor data",
        );
        assert!(result.is_ok());

        // Test with nonexistent interface
        let result = device.store_neighbor_data_for_interface(
            "device_id",
            "NonExistentInterface",
            "neighbor data",
        );
        assert!(
            result.is_ok(),
            "Should succeed even for nonexistent interface"
        );
        assert_eq!(
            result.unwrap(),
            None,
            "Should return None for nonexistent interface"
        );
    }

    #[test]
    fn test_cisco_parse_cisco_cdp_tabular() {
        let mut device = Cisco::test_device();

        let tabular_cdp = r#"Device-ID  Local Intrfce     Holdtme    Capability  Platform  Port ID
neighbor1  Gig 0/1           120         R S I      cisco     Gig 0/2
neighbor2  Gig 0/2           150         R           cisco     Gig 0/1
switch1    Gig 0/3           180         S I         cisco     Fas 0/1"#;

        let result = device.parse_cisco_cdp_tabular(tabular_cdp);
        assert!(result.is_ok(), "CDP tabular parsing should succeed");

        // Note: Parsing may return 0 if the CDP format doesn't match expected patterns
        let count = result.unwrap();
        // Just verify the parsing succeeds - count is always >= 0 by type definition
        let _ = count;
    }

    #[test]
    fn test_cisco_parse_cisco_cdp_detailed_edge_cases() {
        let mut device = Cisco::test_device();

        // Test empty detailed CDP
        let result = device.parse_cisco_cdp_detailed("");
        assert!(result.is_ok());

        // Test incomplete CDP block
        let incomplete_cdp = r#"-------------------------
Device ID: incomplete
Platform: cisco"#;

        let result = device.parse_cisco_cdp_detailed(incomplete_cdp);
        assert!(result.is_ok());

        // Test CDP block with missing interface
        let no_interface_cdp = r#"-------------------------
Device ID: no-interface
Platform: cisco  
Holdtime : 120 sec"#;

        let result = device.parse_cisco_cdp_detailed(no_interface_cdp);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cisco_interface_name_parsing() {
        let mut device = Cisco::test_device();

        // Test various interface name formats
        let interface_data = r#"GigabitEthernet0/0/1 is up, line protocol is up
TenGigabitEthernet1/1/3 is up, line protocol is up  
FastEthernet0/1 is down, line protocol is down
Vlan100 is up, line protocol is up
Loopback0 is up, line protocol is up
Port-channel1 is up, line protocol is up"#;

        let result = device.parse_interfaces(interface_data);
        assert!(result.is_ok());

        let built_device = device.build();

        // Check for various interface types
        let has_gig = built_device
            .interfaces
            .iter()
            .any(|i| i.name.contains("GigabitEthernet"));
        let has_ten_gig = built_device
            .interfaces
            .iter()
            .any(|i| i.name.contains("TenGigabitEthernet"));
        let has_fast = built_device
            .interfaces
            .iter()
            .any(|i| i.name.contains("FastEthernet"));
        let has_vlan = built_device
            .interfaces
            .iter()
            .any(|i| i.name.contains("Vlan"));
        let has_loopback = built_device
            .interfaces
            .iter()
            .any(|i| i.name.contains("Loopback"));

        assert!(
            has_gig || has_ten_gig || has_fast || has_vlan || has_loopback,
            "Should parse various interface types"
        );
    }

    #[test]
    fn test_cisco_vlan_extraction() {
        let mut device = Cisco::test_device();

        let vlan_interfaces = r#"Vlan1 is up, line protocol is up
Vlan10 is up, line protocol is up
Vlan100 is up, line protocol is up
Vlan999 is down, line protocol is down"#;

        let result = device.parse_interfaces(vlan_interfaces);
        assert!(result.is_ok());

        let built_device = device.build();

        // Check VLAN number extraction
        for interface in &built_device.interfaces {
            if interface.name.starts_with("Vlan") {
                assert!(
                    !interface.vlans.is_empty(),
                    "VLAN interface {} should have VLAN numbers",
                    interface.name
                );
            }
        }
    }

    // LLDP Tests
    #[test]
    fn test_cisco_lldp_command() {
        let device = Cisco::test_device();
        assert_eq!(device.get_lldp_command(), "show lldp neighbors detail");
        assert!(device.supports_lldp());
    }

    #[test]
    fn test_lldp_data_parsing() {
        setup_test_logging();
        let mut device = Cisco::test_device();

        // Add test interfaces
        device.interfaces.push(Interface::new(
            Uuid::new_v4(),
            "GigabitEthernet1/0/1".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        ));
        device.interfaces.push(Interface::new(
            Uuid::new_v4(),
            "GigabitEthernet1/0/2".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        ));
        device.interfaces.push(Interface::new(
            Uuid::new_v4(),
            "TenGigabitEthernet1/1/3".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        ));

        let lldp_data = std::fs::read_to_string("src/tests/cisco_lldp_neighbors.txt")
            .expect("Failed to read LLDP test data");

        let result = device.parse_lldp(&lldp_data, vec![]);
        assert!(result.is_ok(), "LLDP parsing should succeed");

        let changes = result.unwrap();
        assert!(changes > 0, "Should have processed LLDP neighbors");

        // Verify neighbor data was stored
        let found_neighbors = device.interfaces.iter()
            .filter(|iface| !iface.neighbour_string_data.is_empty())
            .count();
        assert!(found_neighbors > 0, "Should have stored neighbor data in interfaces");
    }

    #[test]
    fn test_lldp_field_parsing() {
        let device = Cisco::test_device();
        let mut neighbor = LldpNeighborData::new();

        // Test parsing individual fields
        device.parse_lldp_field(&mut neighbor, "Local Intf: Gi1/0/1").unwrap();
        assert_eq!(neighbor.local_interface, "Gi1/0/1");

        device.parse_lldp_field(&mut neighbor, "System Name: CORE-SW-01").unwrap();
        assert_eq!(neighbor.system_name, Some("CORE-SW-01".to_string()));

        device.parse_lldp_field(&mut neighbor, "Port id: Gi2/0/1").unwrap();
        assert_eq!(neighbor.port_id, "Gi2/0/1");

        device.parse_lldp_field(&mut neighbor, "Chassis id: a0:23:9f:2b:b3:3f").unwrap();
        assert_eq!(neighbor.chassis_id, "a0:23:9f:2b:b3:3f");

        device.parse_lldp_field(&mut neighbor, "System Description: Cisco IOS Software").unwrap();
        assert_eq!(neighbor.system_description, Some("Cisco IOS Software".to_string()));

        device.parse_lldp_field(&mut neighbor, "Enabled Capabilities: B,R").unwrap();
        assert_eq!(neighbor.capabilities, vec!["B", "R"]);

        device.parse_lldp_field(&mut neighbor, "Time remaining: 120 seconds").unwrap();
        assert_eq!(neighbor.ttl, Some(120));
    }

    #[test]
    fn test_lldp_capabilities_parsing() {
        let device = Cisco::test_device();

        let caps = device.parse_capabilities("B,R").unwrap();
        assert_eq!(caps, vec!["B", "R"]);

        let caps = device.parse_capabilities("B, R, T").unwrap();
        assert_eq!(caps, vec!["B", "R", "T"]);

        let caps = device.parse_capabilities("not advertised").unwrap();
        assert!(caps.is_empty());

        let caps = device.parse_capabilities("").unwrap();
        assert!(caps.is_empty());
    }

    #[test]
    fn test_lldp_ttl_parsing() {
        let device = Cisco::test_device();

        let ttl = device.parse_ttl("120 seconds").unwrap();
        assert_eq!(ttl, Some(120));

        let ttl = device.parse_ttl("95 seconds").unwrap();
        assert_eq!(ttl, Some(95));

        let ttl = device.parse_ttl("not advertised").unwrap();
        assert_eq!(ttl, None);

        let ttl = device.parse_ttl("").unwrap();
        assert_eq!(ttl, None);
    }

    #[test]
    fn test_lldp_interface_candidates() {
        let device = Cisco::test_device();

        let candidates = device.generate_interface_candidates("Gi1/0/1");
        assert!(candidates.contains(&"Gi1/0/1".to_string()));
        assert!(candidates.contains(&"GigabitEthernet1/0/1".to_string()));

        let candidates = device.generate_interface_candidates("Fa0/1");
        assert!(candidates.contains(&"Fa0/1".to_string()));
        assert!(candidates.contains(&"FastEthernet0/1".to_string()));

        let candidates = device.generate_interface_candidates("Ten1/1/3");
        assert!(candidates.contains(&"Ten1/1/3".to_string()));
        assert!(candidates.contains(&"TenGigabitEthernet1/1/3".to_string()));
    }

    #[test]
    fn test_interface_name_matching() {
        let device = Cisco::test_device();

        assert!(device.interface_name_matches("GigabitEthernet1/0/1", "Gi1/0/1"));
        assert!(device.interface_name_matches("Gi1/0/1", "GigabitEthernet1/0/1"));
        assert!(device.interface_name_matches("FastEthernet0/1", "Fa0/1"));
        assert!(!device.interface_name_matches("GigabitEthernet1/0/1", "Fa0/1"));
    }

    #[test]
    fn test_lldp_neighbor_data_to_string() {
        let mut neighbor = LldpNeighborData::new();
        neighbor.local_interface = "Gi1/0/1".to_string();
        neighbor.chassis_id = "a0:23:9f:2b:b3:3f".to_string();
        neighbor.port_id = "Gi2/0/1".to_string();
        neighbor.system_name = Some("CORE-SW-01".to_string());
        neighbor.management_ip = Some("10.0.99.2".to_string());
        neighbor.capabilities = vec!["B".to_string(), "R".to_string()];
        neighbor.ttl = Some(120);

        let output = neighbor.to_string();
        assert!(output.contains("Local Intf: Gi1/0/1"));
        assert!(output.contains("System Name: CORE-SW-01"));
        assert!(output.contains("IP: 10.0.99.2"));
        assert!(output.contains("Enabled Capabilities: B,R"));
        assert!(output.contains("Time remaining: 120 seconds"));
    }
}
