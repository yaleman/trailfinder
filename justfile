# Justfile for trailfinder project

# Run clippy on all targets
clippy:
    cargo clippy --all-targets

# Run tests
test:
    cargo test

# Run tests with output
test-verbose:
    cargo test -- --nocapture

# Format code
fmt:
    cargo fmt

# Check code without building
cargo-check:
    cargo check

# Build the project
build:
    cargo build

# Build for release
build-release:
    cargo build --release

# Run the application
run:
    cargo run

# Clean build artifacts
clean:
    cargo clean

# Run all checks (clippy, fmt, test)
check: fmt clippy test