pub mod cisco;
pub mod mikrotik;
pub(crate) mod prelude;

use crate::config::{DeviceConfig, DeviceState};
use crate::ssh::SshClient;
use prelude::*;
use uuid::Uuid;

pub trait DeviceHandler {
    const GET_IP_COMMAND: &'static str;
    const GET_IDENTITY_COMMAND: &'static str;
    const GET_IPSEC_COMMAND: &'static str;

    fn new(hostname: String, name: Option<String>, owner: Owner, device_type: DeviceType) -> Self;
    fn parse_interfaces(&mut self, input_data: &str) -> Result<(), TrailFinderError>;
    fn parse_routes(&mut self, input_data: &str) -> Result<(), TrailFinderError>;
    fn parse_neighbours(
        &mut self,
        input_data: &str,
        devices: Vec<Device>,
    ) -> Result<usize, TrailFinderError>;

    fn parse_identity(&mut self, input_data: &str) -> Result<(), TrailFinderError>;
    fn parse_ip_addresses(&mut self, input_data: &str) -> Result<(), TrailFinderError>;
    fn parse_ipsec(&mut self, input_data: &str) -> Result<(), TrailFinderError>;

    fn build(self) -> Device;

    /// Find an interface by name
    fn interface_by_name(&self, name: &str) -> Option<Uuid>;

    fn get_interfaces_command(&self) -> String;
    fn get_routes_command(&self) -> String;
    fn get_cdp_command(&self) -> String;

    fn interrogate_device(
        &self,
        ssh_client: &mut SshClient,
        device_config: &DeviceConfig,
        device_type: DeviceType,
    ) -> impl std::future::Future<Output = Result<DeviceState, TrailFinderError>> + Send;
}

use crate::config::DeviceBrand;

pub async fn interrogate_device_by_brand(
    brand: DeviceBrand,
    ssh_client: &mut SshClient,
    device_config: &DeviceConfig,
    device_type: DeviceType,
) -> Result<DeviceState, TrailFinderError> {
    match brand {
        DeviceBrand::Mikrotik => {
            let interrogator = mikrotik::Mikrotik::new(
                "temp".to_string(),
                None,
                Owner::Unknown,
                DeviceType::Router,
            );
            interrogator
                .interrogate_device(ssh_client, device_config, device_type)
                .await
        }
        DeviceBrand::Cisco => {
            let interrogator =
                cisco::Cisco::new("temp".to_string(), None, Owner::Unknown, DeviceType::Router);
            interrogator
                .interrogate_device(ssh_client, device_config, device_type)
                .await
        }
        _ => Err(TrailFinderError::Generic(format!(
            "Interrogation not supported for brand {:?}",
            brand
        ))),
    }
}
