//! ModelMux Models API - Model Caching and Selection
//!
//! Provides model caching, selection, and proxy routing similar to Kilo.ai Gateway.
//! Boots from env and .env config, caches model selections.

pub mod cache;
pub mod registry;
pub mod proxy;

pub use cache::{CachedModel, ModelCache};
pub use registry::{ModelRegistry, ModelEntry, ProviderEntry};
pub use proxy::{ModelProxy, ProxyConfig, ProxyRoute};
