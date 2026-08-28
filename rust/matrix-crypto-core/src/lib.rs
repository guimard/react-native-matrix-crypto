//! Core logic for the Matrix crypto bridge.
//!
//! This crate knows nothing about UniFFI, JSI, or React Native. It must never
//! take a direct dependency on `uniffi`; `scripts/assert-core-boundary.sh`
//! enforces that in CI.

mod error;
mod identity;
mod machine;
mod observer;
mod probe;
mod runtime;

pub use error::ProbeError;
pub use identity::{device_identity_keys, IdentityKeys};
pub use machine::{create_machine, open_store, with_machine, MachineConfig, MachineError};
pub use observer::{probe_with_observer, ProbeObserver, ProbeSignal};
pub use probe::{probe, ProbeReport};
pub use runtime::in_runtime;
