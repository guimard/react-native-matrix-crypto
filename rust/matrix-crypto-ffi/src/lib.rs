//! UniFFI surface for the Matrix crypto bridge.
//!
//! This crate contains type translation and nothing else. All logic lives in
//! `matrix-crypto-core`. If you are tempted to add a branch here, it belongs
//! in the core.

use matrix_crypto_core::{ProbeError, ProbeReport as CoreProbeReport};

uniffi::setup_scaffolding!("matrix_crypto");

/// Mirror of the core's report, carrying the UniFFI record derive.
#[derive(Debug, uniffi::Record)]
pub struct ProbeReport {
    pub echoed: String,
    pub payload: Vec<u8>,
    pub core_version: String,
}

impl From<CoreProbeReport> for ProbeReport {
    fn from(r: CoreProbeReport) -> Self {
        let CoreProbeReport {
            echoed,
            payload,
            core_version,
        } = r;
        Self {
            echoed,
            payload,
            core_version,
        }
    }
}

/// Mirror of the core's error, carrying the UniFFI error derive.
#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum ProbeFfiError {
    #[error("probe rejected: {reason}")]
    Rejected { reason: String },
}

impl From<ProbeError> for ProbeFfiError {
    fn from(e: ProbeError) -> Self {
        match e {
            ProbeError::Rejected { reason } => Self::Rejected { reason },
        }
    }
}

/// A plain `async fn`. UniFFI maps this to a JavaScript Promise on its own;
/// no `async_runtime` attribute is needed until the core's futures require a
/// specific reactor. See the M1b task.
#[uniffi::export]
pub async fn probe(input: String, payload: Vec<u8>) -> Result<ProbeReport, ProbeFfiError> {
    matrix_crypto_core::probe(input, payload)
        .await
        .map(Into::into)
        .map_err(Into::into)
}

use std::sync::Arc;

/// Mirror of the core's signal, carrying the UniFFI record derive.
#[derive(uniffi::Record)]
pub struct ProbeSignal {
    pub kind: String,
    pub detail: String,
}

/// `with_foreign` makes this implementable from JavaScript.
#[uniffi::export(with_foreign)]
pub trait ProbeObserver: Send + Sync {
    fn on_signal(&self, signal: ProbeSignal);
}

/// Translation only: adapts the foreign observer to the core's trait.
struct ObserverAdapter(Arc<dyn ProbeObserver>);

impl matrix_crypto_core::ProbeObserver for ObserverAdapter {
    fn on_signal(&self, signal: matrix_crypto_core::ProbeSignal) {
        // Destructured, not field-accessed: a new core field must fail to
        // compile here rather than be silently dropped. See Global Constraints.
        let matrix_crypto_core::ProbeSignal { kind, detail } = signal;
        self.0.on_signal(ProbeSignal { kind, detail });
    }
}

#[uniffi::export]
pub async fn probe_with_observer(
    input: String,
    payload: Vec<u8>,
    observer: Arc<dyn ProbeObserver>,
) -> Result<ProbeReport, ProbeFfiError> {
    let adapter = Arc::new(ObserverAdapter(observer));
    matrix_crypto_core::probe_with_observer(input, payload, adapter)
        .await
        .map(Into::into)
        .map_err(Into::into)
}

/// Mirror of the core's identity keys, carrying the UniFFI record derive.
#[derive(Debug, uniffi::Record)]
pub struct IdentityKeys {
    pub curve25519: String,
    pub ed25519: String,
}

/// Mirror of the core's identity error, carrying the UniFFI error derive.
#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum IdentityFfiError {
    #[error("malformed identifier: {detail}")]
    MalformedIdentifier { detail: String },
}

/// A plain `async fn`, matching `probe`: this function's own path --
/// `OlmMachine::new` plus an in-memory store -- calls no `spawn` and needs no
/// reactor, confirmed by reading the vendored source and by clean device runs
/// (iOS simulator and a physical Android device, no panic).
///
/// That is scoped to this one function, not a resolution for
/// `matrix-sdk-crypto` as a whole. `matrix-sdk-common`, a mandatory
/// dependency, enables tokio's `rt` feature on every native target and
/// re-exports `tokio::task::spawn`; `matrix-sdk-crypto` calls it from
/// production code this crate does not yet expose, including
/// `OlmMachine::share_room_key` (the Megolm key-sharing entry point a later
/// milestone needs). See spec section 5.1: the async-runtime question is
/// scoped to what this task exercised, not closed for the crate.
#[uniffi::export]
pub async fn device_identity_keys(
    user_id: String,
    device_id: String,
) -> Result<IdentityKeys, IdentityFfiError> {
    matrix_crypto_core::device_identity_keys(&user_id, &device_id)
        .await
        .map(|k| {
            // Destructured, not field-accessed. See Global Constraints.
            let matrix_crypto_core::IdentityKeys {
                curve25519,
                ed25519,
            } = k;
            IdentityKeys {
                curve25519,
                ed25519,
            }
        })
        .map_err(|e| match e {
            matrix_crypto_core::IdentityError::MalformedIdentifier { detail } => {
                IdentityFfiError::MalformedIdentifier { detail }
            }
        })
}
