//! Core logic for the Matrix crypto bridge.
//!
//! This crate knows nothing about UniFFI, JSI, or React Native. It must never
//! take a direct dependency on `uniffi`; `scripts/assert-core-boundary.sh`
//! enforces that in CI.
