pub mod protocol_detector;
pub mod patricia_detector_simd;
#[cfg(target_arch = "aarch64")]
pub mod patricia_detector_simd_arm64;

// Static code generation modules
pub mod combinator_dsl;
#[cfg(feature = "static-generation")]
pub mod static_generation;
#[cfg(feature = "static-generation")]
pub mod jump_table_generation;
pub mod n_dimensional_inference;
pub mod fixed_range_constraints;
pub mod autovec_optimization;
pub mod pac;
pub mod bonjour;
pub mod upnp;
pub mod auto_discovery;
pub mod types;
pub mod note20_features;
pub mod unified_handler;
pub mod universal_listener;
pub mod protocol_registry;
pub mod protocol_handlers;
pub mod simple_routing;
pub mod unified_protocol_manager;
pub mod posix_sockets;
// RBCursive - Network parser combinators with SIMD acceleration
pub mod rbcursive;
// Testing and mock modules
pub mod protocol_mocks;
pub mod simple_torture_test;
pub mod abstractions;
pub mod stubs;