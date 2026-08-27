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
