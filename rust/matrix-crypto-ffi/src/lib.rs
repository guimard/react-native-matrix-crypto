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

/// Mirror of the core's machine error, carrying the UniFFI error derive.
///
/// Replaces `IdentityFfiError`: the core function below now reads the live,
/// store-backed machine through `matrix_crypto_core::with_machine` rather
/// than building a throwaway one, so its error is the core's `MachineError`.
#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum MachineFfiError {
    #[error("no crypto machine has been created")]
    NotInitialised,
    #[error("a crypto machine already exists with a different configuration")]
    AlreadyInitialised,
    #[error("malformed identifier: {detail}")]
    MalformedIdentifier { detail: String },
    #[error("store error: {detail}")]
    Store { detail: String },
    #[error("the store belongs to a different account")]
    MismatchedAccount,
}

impl From<matrix_crypto_core::MachineError> for MachineFfiError {
    fn from(e: matrix_crypto_core::MachineError) -> Self {
        // Exhaustive, no wildcard arm. See Global Constraints.
        match e {
            matrix_crypto_core::MachineError::NotInitialised => Self::NotInitialised,
            matrix_crypto_core::MachineError::AlreadyInitialised => Self::AlreadyInitialised,
            matrix_crypto_core::MachineError::MalformedIdentifier { detail } => {
                Self::MalformedIdentifier { detail }
            }
            matrix_crypto_core::MachineError::Store { detail } => Self::Store { detail },
            matrix_crypto_core::MachineError::MismatchedAccount => Self::MismatchedAccount,
        }
    }
}

/// Mirror of the core's machine config, carrying the UniFFI record derive.
///
/// No `Debug` derive, unlike `ProbeReport`/`IdentityKeys` above: this record
/// carries the store passphrase, which must never reach a log or an error
/// message (see Global Constraints), and a derived `Debug` would leave it
/// one accidental `{:?}` away from doing exactly that.
#[derive(uniffi::Record)]
pub struct CryptoMachineConfig {
    pub user_id: String,
    pub device_id: String,
    pub store_path: String,
    pub store_passphrase: Option<String>,
}

impl From<CryptoMachineConfig> for matrix_crypto_core::MachineConfig {
    fn from(value: CryptoMachineConfig) -> Self {
        // Destructured, not field-accessed: a field added to the core config
        // later must fail this build rather than being silently dropped. See
        // Global Constraints.
        let CryptoMachineConfig {
            user_id,
            device_id,
            store_path,
            store_passphrase,
        } = value;
        Self {
            user_id,
            device_id,
            store_path,
            store_passphrase,
        }
    }
}

/// A plain `async fn`, matching `device_identity_keys` below: the core
/// function this calls reaches for a runtime explicitly, via
/// `matrix-crypto-core::runtime::in_runtime`, wherever the store it builds
/// needs one -- so no `async_runtime` attribute is needed here either.
#[uniffi::export]
pub async fn create_crypto_machine(config: CryptoMachineConfig) -> Result<(), MachineFfiError> {
    matrix_crypto_core::create_machine(config.into())
        .await
        .map_err(Into::into)
}

/// Reopens a store written by an earlier process. Mirrors `open_store`,
/// which is the same operation as `create_machine` under a name that says
/// what the caller means; see that function's own doc comment in
/// `matrix-crypto-core::machine`.
#[uniffi::export]
pub async fn open_crypto_store(config: CryptoMachineConfig) -> Result<(), MachineFfiError> {
    matrix_crypto_core::open_store(config.into())
        .await
        .map_err(Into::into)
}

/// A plain `async fn`, matching `probe`: no `async_runtime` attribute is
/// needed here either. `device_identity_keys` reads the live machine through
/// `with_machine`, which locks a `tokio::sync::Mutex` -- a primitive that
/// needs no reactor of its own, unlike the tokio filesystem and
/// connection-pool primitives `create_machine`/`open_store` use internally to
/// build that machine in the first place (see
/// `matrix-crypto-core::runtime::in_runtime`, which supplies the runtime
/// those need explicitly rather than relying on an ambient one).
#[uniffi::export]
pub async fn device_identity_keys(
    user_id: String,
    device_id: String,
) -> Result<IdentityKeys, MachineFfiError> {
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
        .map_err(Into::into)
}
