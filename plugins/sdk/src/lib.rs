//! Kinetix plugin SDK.
//!
//! This crate is the author-facing side of the plugin ABI documented in
//! `docs/KINETIX-PLUGIN-ARCHITECTURE.md`. It generates the WIT bindings for the
//! `plugin` world, re-exports them, and provides small helpers for the parts of
//! a plugin that are boilerplate (reading host KV, publishing cached facts,
//! constructing `PluginError`s).
//!
//! A plugin crate depends on this SDK, implements the `Guest` traits for the
//! capabilities it declares, and calls [`export!`]:
//!
//! ```ignore
//! use kinetix_plugin_sdk::{exports, kinetix, export};
//! use kinetix::plugin::types::*;
//!
//! struct Component;
//! impl exports::credential_strategy::Guest for Component { /* ... */ }
//! export!(Component with_types_in kinetix_plugin_sdk);
//! ```
//!
//! The ABI is the WIT interface, not this crate: the SDK only removes
//! boilerplate and never changes what the host enforces.

pub mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "plugin",
        pub_export_macro: true,
    });
}

/// Bindings for optional credential-aware model discovery.
pub mod model_source_v2 {
    wit_bindgen::generate!({
        path: "wit",
        world: "plugin-model-source-v2",
        pub_export_macro: true,
    });
}

/// Bindings for the optional browser/account authorization world.
pub mod auth {
    wit_bindgen::generate!({
        path: "wit",
        world: "plugin-auth",
        pub_export_macro: true,
    });
}

/// Bindings for the `plugin-adapter` world (§6.3). A component that provides a
/// `provider-adapter` capability implements `adapter::exports::provider_adapter::Guest`
/// and invokes `adapter::export!(Component with_types_in kinetix_plugin_sdk::adapter)`.
pub mod adapter {
    wit_bindgen::generate!({
        path: "wit",
        world: "plugin-adapter",
        pub_export_macro: true,
    });
}

pub use bindings::export;
pub use bindings::{exports, kinetix};

pub mod prelude {
    pub use crate::bindings::{exports, kinetix};
    pub use crate::export;
    pub use crate::helpers::*;
}

pub mod helpers;
