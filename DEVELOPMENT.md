# LiteBike Development Guide

## Feature Flag System

LiteBike uses a feature flag system to separate stable production features from experimental development work.

### Available Feature Flags

```toml
[features]
default = []                    # Stable features only
unstable = ["intel-console", "experimental-gates"]
intel-console = []             # Protocol reverse engineering console
experimental-gates = []        # Advanced protocol gates
full = ["unstable"]           # All features enabled
```

### Building with Feature Flags

```bash
# Default build (stable features only)
cargo build --release

# Build with unstable features
cargo build --release --features unstable

# Build with specific experimental features
cargo build --release --features intel-console

# Build with all features
cargo build --release --features full
```

### Testing Different Feature Combinations

```bash
# Test stable features
cargo test

# Test with unstable features
cargo test --features unstable

# Test specific feature combinations
cargo test --features intel-console
```

## Development Workflow

### Adding New Features

1. **Stable Features**: Add directly to existing modules
2. **Experimental Features**: Gate behind feature flags

```rust
// In src/lib.rs
#[cfg(feature = "my-feature")]
pub mod my_experimental_module;

// In src/bin/litebike.rs
#[cfg(feature = "my-feature")]
("my-command", run_my_command),

#[cfg(feature = "my-feature")]
fn run_my_command(args: &[String]) {
    // Implementation
}
```

### RBCursive Integration

All new protocol handlers should integrate with the RBCursive engine:

```rust
use litebike::rbcursive::{RBCursive, PatternType};

fn my_protocol_handler(data: &[u8]) {
    let rbcursive = RBCursive::new();
    
    // Use protocol detection
    let detection = rbcursive.detect_protocol(data);
    
    // Use pattern matching
    let result = rbcursive.match_regex(data, r"my-pattern");
    
    // Use SIMD scanning
    let matches = rbcursive.scan_with_pattern(data, "*.txt", PatternType::Glob);
}
```

### Code Style Guidelines

1. **No Comments**: Unless explicitly requested, avoid adding comments
2. **Error Handling**: Use `Result` types for error propagation
3. **SIMD Integration**: Use RBCursive for all pattern matching and protocol detection
4. **Cross-Platform**: Ensure code works on Android/Termux, macOS, and Linux
5. **Direct Syscalls**: Prefer direct syscalls over /proc, /sys dependencies

### Testing Requirements

1. **Unit Tests**: Test individual functions and modules
2. **Integration Tests**: Test command-line interface
3. **Cross-Platform Tests**: Ensure functionality on all supported platforms
4. **Feature Flag Tests**: Test both with and without feature flags

### Documentation Standards

1. **README.md**: Update with new stable features
2. **CLAUDE.md**: Update development instructions
3. **Code Documentation**: Use rustdoc for public APIs
4. **Examples**: Provide practical usage examples

## Experimental Features

### Intel Console (Planned)

The Intel Console is designed for protocol reverse engineering:

- **Protocol Interception**: MITM proxy capabilities
- **Wireshark-Style Filtering**: Advanced protocol filtering
- **strace-Style Tracing**: System call tracing
- **RBCursive Integration**: Anchor matrix visualization

### Implementation Guidelines

```rust
// Feature-gated module structure
#[cfg(feature = "intel-console")]
pub mod intel_console {
    pub mod interceptor;
    pub mod filters;
    pub mod analyzer;
    pub mod replay;
}
```

### Graduation Path

Features graduate from experimental to stable when they:

1. **Pass All Tests**: Including cross-platform testing
2. **Have Documentation**: Complete API documentation
3. **Are Performance Tested**: Benchmarks show acceptable performance
4. **Are API Stable**: No breaking changes expected
5. **Have User Feedback**: Positive feedback from early adopters

## Universal Installation

All builds should support the universal installation pattern:

```bash
# Build and install
cargo build --release
mkdir -p ~/.litebike/bin
cp target/release/litebike ~/.litebike/bin/
chmod +x ~/.litebike/bin/litebike

# Add to PATH (once)
echo 'export PATH="$HOME/.litebike/bin:$PATH"' >> ~/.bashrc
```

## Contributing

1. **Fork the Repository**: Create your own fork
2. **Create Feature Branch**: `git checkout -b feature/my-feature`
3. **Follow Guidelines**: Use feature flags for experimental work
4. **Test Thoroughly**: Test on multiple platforms
5. **Update Documentation**: Keep README.md current
6. **Submit Pull Request**: With clear description of changes

### Pull Request Requirements

- [ ] Tests pass on all platforms
- [ ] Documentation updated
- [ ] Feature flags used appropriately
- [ ] No breaking changes to stable APIs
- [ ] RBCursive integration where applicable
- [ ] Cross-platform compatibility verified

## Debugging and Profiling

### Debug Builds

```bash
# Debug build with all features
cargo build --features full

# Run with debug logging
RUST_LOG=debug ./target/debug/litebike <command>
```

### Performance Analysis

```bash
# Benchmark pattern matching
litebike pattern-bench 1048576

# Profile with perf (Linux)
perf record --call-graph=dwarf ./litebike pattern-bench
perf report

# Profile memory usage
valgrind --tool=massif ./litebike <command>
```

### Cross-Platform Testing

```bash
# Android/Termux
pkg install rust
cargo build --target aarch64-linux-android

# macOS
cargo build --target x86_64-apple-darwin
cargo build --target aarch64-apple-darwin

# Linux
cargo build --target x86_64-unknown-linux-gnu
```

## Architecture Decisions

### RBCursive Engine

The RBCursive engine provides:
- **SIMD-accelerated parsing**
- **Compile-time protocol validation**
- **Zero-allocation anchor matrix**
- **Composable parse combinators**

All new protocol work should leverage RBCursive rather than implementing custom parsers.

### Feature Flag Philosophy

- **default = []**: Only stable, production-ready features
- **unstable**: Experimental features under active development
- **Specific flags**: Fine-grained control for testing and development

This allows users to opt-into experimental features while keeping the default build stable and reliable.