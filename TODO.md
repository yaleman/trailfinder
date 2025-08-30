# Trailfinder TODO: Brand Interrogation Trait Refactor

## Overview
Refactor per-brand interrogation commands into a trait system and improve Device struct field semantics.

## Problem Summary
1. **Device struct missing hostname**: Currently uses `name` field as UUID fallback instead of actual hostname
2. **Hard-coded interrogation commands**: SSH commands are manually coded in `main.rs` functions 
3. **Poor separation of concerns**: Brand-specific logic is scattered rather than encapsulated

## Implementation Plan

### Phase 1: Update Device struct fields
- [x] Add `device_id` field of type `uuid::Uuid` to `Device` struct
- [x] Add `hostname` field of type `String` to `Device` struct 
- [x] Change existing `name` field to `Option<String>` for optional human-readable device names
- [x] Add `display_name()` method to Device that returns name if present, otherwise hostname
- [x] Update `Device::new()` constructor to accept hostname parameter and generate UUID for device_id
- [x] Fix `interface_id()` method to use device_id instead of name
- [x] Update `find_interface_by_id()` method to use device_id consistently

### Phase 2: Create DeviceInterrogator trait
- [x] Create new `DeviceInterrogator` trait in `src/brand/mod.rs`
- [x] Define async methods:
  - `get_interfaces_command(&self) -> String` (returns the command string)
  - `get_routes_command(&self) -> String` (returns the command string)
  - `interrogate_device(ssh_client, device_config, device_type) -> DeviceState`

### Phase 3: Implement trait for each brand
- [x] Implement `DeviceInterrogator` for `Mikrotik` struct
  - `get_interfaces_command()` returns `"/interface print".to_string()`
  - `get_routes_command()` returns `"/ip route print".to_string()`
  - Uses existing `ConfParser` for parsing logic
- [x] Implement `DeviceInterrogator` for `Cisco` struct  
  - `get_interfaces_command()` returns `"show interfaces".to_string()`
  - `get_routes_command()` returns `"show ip route".to_string()`
  - Uses existing `ConfParser` for parsing logic
- [x] Update brand parsers to use hostname parameter

### Phase 4: Refactor main.rs interrogation logic
- [x] Replace hard-coded `interrogate_mikrotik_device()` and `interrogate_cisco_device()` functions
- [x] Create generic `interrogate_device_by_brand()` function that:
  - Uses trait methods instead of hard-coded commands
  - Handles brand-specific interrogation via async trait methods
- [x] Update match statement in `identify_and_interrogate_device()` to use trait-based approach

### Phase 5: Update brand factory pattern
- [x] Add factory function `interrogate_device_by_brand()` based on `DeviceBrand`
- [x] This enables clean separation and easy extension for new brands

### Phase 6: Testing
- [x] Test the refactored code with existing devices
- [x] Ensure all existing functionality still works  
- [x] Verify interface IDs are stable with device_id

### Additional: Remove force requirement from update command
- [x] Remove `--force` flag requirement from update command
- [x] Update command now always performs fresh updates

## Benefits
- **Cleaner architecture**: Brand-specific commands encapsulated in brand implementations
- **Easy extensibility**: Adding new brands only requires implementing the trait
- **Better separation of concerns**: SSH logic separated from parsing logic
- **Proper ID semantics**: interface_id uses stable device_id UUID instead of changeable name
- **Flexible naming**: device_id (UUID), name (optional human readable), hostname (network address)
- **Smart display logic**: Shows name if available, otherwise falls back to hostname
- **Maintainable code**: No more scattered brand-specific logic in main.rs

## Files to Modify
- `src/lib.rs`: Update Device struct with new fields and methods
- `src/brand/mod.rs`: Add DeviceInterrogator trait  
- `src/brand/mikrotik.rs`: Implement DeviceInterrogator, update to use hostname
- `src/brand/cisco.rs`: Implement DeviceInterrogator, update to use hostname
- `src/main.rs`: Refactor interrogation logic to use traits