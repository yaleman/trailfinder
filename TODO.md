# Trailfinder TODO

## Priority Implementation: Global CDP/Neighbor Discovery System

### Phase 1: Enhanced Type System and Dependencies ✅
- [x] Add mac_address crate dependency with serde support
- [x] Create PeerConnection enum (Untagged, Vlan(u16), Trunk, Management, Tunnel(String))
- [x] Update Interface struct with `mac_address: Option<MacAddress>` field
- [x] Change peers to `HashMap<PeerConnection, Vec<Uuid>>` for type safety

### Phase 2: Enhanced NeighborInfo with UUID References ✅
- [x] Create NeighborInfo struct with UUID-based local interface references
- [x] Include MAC addresses, connection types, and discovery protocols
- [x] Parse VLAN information to determine PeerConnection types
- [x] Map interface names to UUIDs during parsing

### Phase 3: Vendor-Specific Implementation ✅
- [x] Update MikroTik parser: extract MAC addresses, detect VLAN connections, resolve interface UUIDs
- [x] Update Cisco parser: parse interface MACs, extract VLAN info from CDP, map to interface UUIDs
- [x] Both parsers: store structured neighbor data for global resolution

### Phase 4: Global Neighbor Resolution System ✅
- [x] Implement `resolve_all_neighbor_relationships(device_states: &mut [DeviceState])`
- [x] Use typed peer relationships with PeerConnection enum
- [x] Establish bidirectional relationships with MAC address validation
- [x] Handle hostname fuzzy matching and device correlation

### Phase 5: Topology Integration ✅
- [x] Generate typed topology connections from peer relationships
- [x] Support VLAN-aware network segmentation
- [x] Display different connection types in topology visualization
- [x] Add CDP connection type to distinguish from routed connections

### Phase 6: Testing and Validation ✅
- [x] Test with live devices: rb5009.housenet.yaleman.org ↔ c3650.housenet.yaleman.org
- [x] Verify cross-vendor neighbor discovery accuracy
- [x] Test VLAN-aware topology generation
- [x] Validate bidirectional peer relationship consistency

## Other Upcoming Features

- [ ] implement proper ssh config parsing because currently it misses some things

### UI changes

- [x] When the route finds an edge that leads to a default gateway that's not linked to another device, it should link to an "internet" node.

### Additional Device Brands

(I'll need someone to give me some loaners :D )

- [ ] Add support for Checkpoint devices
- [ ] Add support for Juniper devices
- [ ] Add support for Arista devices

### Enhanced CLI Features

- [ ] config-dump that shows the "running" appconfig after parsing
- [ ] Add device discovery via network scanning

## Documentation

- [ ] Add usage examples to README
- [ ] Add troubleshooting guide for common issues

### SSH Agent Support

- [ ] Implement full SSH agent authentication support
- [ ] Add proper russh agent integration for encrypted keys
- [ ] Test with various SSH agent configurations
