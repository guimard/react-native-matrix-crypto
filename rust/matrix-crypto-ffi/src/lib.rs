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
///
/// No thread-safety work happens here, and none is needed. By the time
/// `on_signal` below runs, the core's emission path has already detached
/// the call onto its own freshly spawned thread, off whatever stack -- and
/// whatever lock -- produced the signal (see `observer.rs`'s `emit` in
/// `matrix-crypto-core`, and design doc section 5). Calling the foreign
/// callback from that thread, whichever one it happens to be, is safe
/// because ubrn's generated glue is what marshals the call onto the JS
/// thread; that marshalling, not this crate, is the boundary a callback
/// crossing into JavaScript from an arbitrary native thread has to cross.
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

/// Mirror of the core's sync outcome, carrying the UniFFI record derive.
///
/// Both counts are plain totals with no payload content, key material or
/// identifier -- see Global Constraints -- so, unlike `Envelope` and
/// `OutgoingRequest` below, a `Debug` derive is safe here.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncOutcome {
    pub to_device_event_count: u32,
    pub new_session_count: u32,
}

impl From<matrix_crypto_core::SyncOutcome> for SyncOutcome {
    fn from(value: matrix_crypto_core::SyncOutcome) -> Self {
        // Destructured, not field-accessed: a field added to the core
        // struct later must fail this build rather than being silently
        // dropped. See Global Constraints.
        let matrix_crypto_core::SyncOutcome {
            to_device_event_count,
            new_session_count,
        } = value;
        Self {
            to_device_event_count,
            new_session_count,
        }
    }
}

/// Mirror of the core's envelope, carrying the UniFFI record derive.
///
/// No `Debug` derive: `ciphertext` is, depending on which call produced
/// this, either the wire ciphertext or the plaintext just recovered from
/// it, and `sender` is a user id -- exactly what the global no-secret rule
/// forbids from any `Debug` output or panic message. The core's own
/// `Envelope` hand-writes a redacting `Debug` for the same reason; this
/// mirror simply carries none, the same choice `CryptoMachineConfig` above
/// already makes for its own secret field.
#[derive(Clone, uniffi::Record)]
pub struct Envelope {
    pub scope: String,
    pub algorithm: String,
    pub event_type: String,
    pub ciphertext: Vec<u8>,
    pub sender: String,
}

impl From<matrix_crypto_core::Envelope> for Envelope {
    fn from(value: matrix_crypto_core::Envelope) -> Self {
        // Destructured, not field-accessed. See Global Constraints.
        let matrix_crypto_core::Envelope {
            scope,
            algorithm,
            event_type,
            ciphertext,
            sender,
        } = value;
        Self {
            scope,
            algorithm,
            event_type,
            ciphertext,
            sender,
        }
    }
}

/// Mirror of the core's outgoing request, carrying the UniFFI record
/// derive.
///
/// No `Debug` derive: `body` can carry an Olm-encrypted payload, device
/// keys or one-time keys, alongside user and device ids throughout -- the
/// same reason `Envelope` above carries none. The core's own
/// `OutgoingRequest` hand-writes a redacting `Debug`; this mirror simply
/// carries none.
#[derive(Clone, uniffi::Record)]
pub struct OutgoingRequest {
    pub id: String,
    pub kind: String,
    pub body: String,
}

impl From<matrix_crypto_core::OutgoingRequest> for OutgoingRequest {
    fn from(value: matrix_crypto_core::OutgoingRequest) -> Self {
        // Destructured, not field-accessed. See Global Constraints.
        let matrix_crypto_core::OutgoingRequest { id, kind, body } = value;
        Self { id, kind, body }
    }
}

/// Mirror of the core's session error, carrying the UniFFI error derive.
///
/// Every variant is fieldless, so the `Debug` derive `thiserror::Error`
/// requires (via its `std::error::Error: Debug` supertrait bound) prints
/// only the variant name -- nothing to redact, unlike `Envelope`/
/// `OutgoingRequest` above.
#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum SessionFfiError {
    #[error("the payload could not be parsed")]
    MalformedPayload,
    #[error("no crypto machine has been created")]
    NotInitialised,
    #[error("the crypto operation failed")]
    Failed,
    #[error("the request id does not match a pending request")]
    UnknownRequest,
    #[error("no key is available to decrypt this event")]
    MissingKey,
    #[error("the session that encrypted this event was not shared with this device")]
    UnsharedSession,
    #[error("the device that encrypted this event is not trusted")]
    UnknownDevice,
    #[error("this event could not be decrypted")]
    Undecryptable,
}

impl From<matrix_crypto_core::SessionError> for SessionFfiError {
    fn from(e: matrix_crypto_core::SessionError) -> Self {
        // Exhaustive, no wildcard arm. See Global Constraints.
        match e {
            matrix_crypto_core::SessionError::MalformedPayload => Self::MalformedPayload,
            matrix_crypto_core::SessionError::NotInitialised => Self::NotInitialised,
            matrix_crypto_core::SessionError::Failed => Self::Failed,
            matrix_crypto_core::SessionError::UnknownRequest => Self::UnknownRequest,
            matrix_crypto_core::SessionError::MissingKey => Self::MissingKey,
            matrix_crypto_core::SessionError::UnsharedSession => Self::UnsharedSession,
            matrix_crypto_core::SessionError::UnknownDevice => Self::UnknownDevice,
            matrix_crypto_core::SessionError::Undecryptable => Self::Undecryptable,
        }
    }
}

/// Feeds the encryption-relevant slice of a `/sync` response into the
/// crypto machine. A plain `async fn`, matching every export above: the
/// core reaches for its own runtime wherever it needs one. Mirrors
/// `receive_sync_changes`; see its own doc comment in
/// `matrix-crypto-core::session`.
#[uniffi::export]
pub async fn receive_sync_changes(raw_json: String) -> Result<SyncOutcome, SessionFfiError> {
    matrix_crypto_core::receive_sync_changes(&raw_json)
        .await
        .map(Into::into)
        .map_err(Into::into)
}

/// Encrypts `payload_json` for `scope`. Mirrors `encrypt_event`; see its
/// own doc comment in `matrix-crypto-core::session`.
#[uniffi::export]
pub async fn encrypt_event(
    scope: String,
    event_type: String,
    payload_json: String,
) -> Result<Envelope, SessionFfiError> {
    matrix_crypto_core::encrypt_event(&scope, &event_type, &payload_json)
        .await
        .map(Into::into)
        .map_err(Into::into)
}

/// Decrypts `raw_json`, an event received for `scope`. Mirrors
/// `decrypt_event`; see its own doc comment in
/// `matrix-crypto-core::session`.
#[uniffi::export]
pub async fn decrypt_event(scope: String, raw_json: String) -> Result<Envelope, SessionFfiError> {
    matrix_crypto_core::decrypt_event(&scope, &raw_json)
        .await
        .map(Into::into)
        .map_err(Into::into)
}

/// Ensures `scope` has a group session and shares it with `users`' known
/// devices. Mirrors `share_scope_key`; see its own doc comment in
/// `matrix-crypto-core::session` for why this is two upstream calls, not
/// one, and the design doc section 3ter for why the ordering matters.
#[uniffi::export]
pub async fn share_scope_key(scope: String, users: Vec<String>) -> Result<(), SessionFfiError> {
    matrix_crypto_core::share_scope_key(&scope, &users)
        .await
        .map_err(Into::into)
}

/// Drains every outstanding outbound request. Mirrors
/// `take_outgoing_requests`; see its own doc comment in
/// `matrix-crypto-core::session` and the design doc section 3bis for why
/// this exists at all: discarding what this returns is the mistake that
/// section is named for.
#[uniffi::export]
pub async fn take_outgoing_requests() -> Result<Vec<OutgoingRequest>, SessionFfiError> {
    matrix_crypto_core::take_outgoing_requests()
        .await
        .map(|requests| requests.into_iter().map(Into::into).collect())
        .map_err(Into::into)
}

/// Reports that the request named by `id` was sent, handing back the
/// server's response. Mirrors `mark_request_sent`; see its own doc comment
/// in `matrix-crypto-core::session`.
#[uniffi::export]
pub async fn mark_request_sent(id: String, response_json: String) -> Result<(), SessionFfiError> {
    matrix_crypto_core::mark_request_sent(&id, &response_json)
        .await
        .map_err(Into::into)
}
