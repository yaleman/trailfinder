pub mod mikrotik;
pub(crate) mod prelude;

use prelude::*;

pub trait ConfParser {
    fn new(name: Option<String>, owner: Owner, device_type: DeviceType) -> Self;
    fn parse_interfaces(&mut self, input_data: &str) -> Result<(), TrailFinderError>;
    fn parse_routes(&mut self, input_data: &str) -> Result<(), TrailFinderError>;
    fn build(self) -> Device;
}
