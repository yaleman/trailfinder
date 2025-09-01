# Trailfinder TODO

## Recently Completed

- [x] Device identity tracking - devices can now identify themselves with system identities separate from hostnames
- [x] MikroTik system identity support via /system/identity/print command
- [x] Cisco hostname parsing and system identity tracking
- [x] Enhanced neighbor resolution with fuzzy hostname matching using both hostname and system identity
- [x] Improved Cisco CDP parsing to handle multi-line detailed output format

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
