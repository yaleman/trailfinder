# Trailfinder TODO

## Active Development

- [ ] complete the ubiquiti support from @ubiquiti_plan.md
- [ ] support ingesting LLDP data from Cisco devices as another source of peer data

## Additional Device Brands

(I'll need someone to give me some loaners :D )

- [ ] Add support for Checkpoint devices
- [ ] Add support for Juniper devices
- [ ] Add support for Arista devices

## Design Improvements

### High Priority (Core Functionality)

#### Architecture & Modularity

- [ ] Implement dependency injection pattern for better testability and modularity
- [ ] Add service layer to encapsulate business logic and reduce coupling between web/CLI layers
- [ ] Separate network discovery into distinct service with pluggable discovery strategies

#### Web Interface & API
- [ ] Add authentication/authorization system for web interface
- [ ] Add bulk operations API endpoints for device management
- [ ] Improve error response consistency across all API endpoints
- [ ] Add input sanitization and validation for all user inputs

### Medium Priority (Scalability)

#### Configuration & State Management
- [ ] Add configuration validation with schema validation and migration support
- [ ] Add environment-based configuration overrides
- [ ] Add audit trail for configuration changes and device state updates (JSON-based)

#### Data Models & Storage
- [ ] Normalize device relationships - currently using string-based lookups instead of proper foreign keys
- [ ] Implement proper data versioning for device configurations (file-based)
- [ ] Add data validation layers at model boundaries
- [ ] Optimize file-based storage for better performance with large networks

#### Performance & Scalability
- [ ] Implement concurrent device discovery with configurable parallelism limits
- [ ] Add result streaming for large topology operations
- [ ] Optimize neighbor discovery algorithms for better performance with large networks
- [ ] Add caching layers for frequently accessed device data

### Low Priority (Polish)

#### Testing & Quality
- [ ] Add integration test suite for end-to-end workflows
- [ ] Implement property-based testing for data model validation
- [ ] Add contract testing for brand parser implementations

#### Developer Experience
- [ ] Add CLI autocomplete support for better usability
- [ ] Implement configuration wizards for initial setup
- [ ] Improve error messages with actionable suggestions

#### Security

- [ ] Implement secure credential storage using system keyring
- [ ] Add TLS certificate validation for HTTPS connections
- [ ] Add comprehensive input validation for all network device data
