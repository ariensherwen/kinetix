//! Plugin subsystem (docs/KINETIX-PLUGIN-ARCHITECTURE.md).
//!
//! This is the post-v1 plugin host: WebAssembly components hosted by Wasmtime
//! with a versioned WIT API. The core rule is that **plugins extend integration
//! behavior; Kinetix owns policy** — plugins supply typed evidence and
//! translation at explicit seams and never select targets, own accounting, or
//! move the commit point.

pub mod adapter;
pub mod credential;
pub mod manager;
pub mod manifest;
pub mod package;
pub mod runtime;
pub mod store;
pub mod types;

pub use manager::PluginManager;

pub use manifest::{HostPolicy, ValidatedManifest};
pub use types::{
    Capability, CircuitState, Integration, Limits, Manifest, Permissions, PluginRef, PluginStatus,
    Provided, MANIFEST_VERSION, PLUGIN_API_MAJOR,
};
