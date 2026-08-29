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
/// the call onto a thread of the library's own -- one of the runtime's
/// blocking-pool threads since M3 replaced the thread per signal, and this
/// comment said "its own freshly spawned thread" until that was noticed --
/// off whatever stack, and whatever lock, produced the signal (see
/// `observer.rs`'s `emit` in `matrix-crypto-core`, and design doc section 5,
/// item B2). What this crate depends on is only that the thread is not the
/// caller's; which thread it is has never mattered here. Calling the foreign
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
    // Appended, never inserted, for the reason `SessionFfiError` below
    // states in full: UniFFI assigns each variant's wire ordinal by
    // declaration position, so inserting one renumbers every variant after
    // it and any binding generated before the insert misdecodes all of
    // them rather than failing cleanly on the one that was added. These
    // three mirror the three the core's `MachineError` grew for verification
    // flows, in the core's own order, because appending to a five-variant
    // list happens to put them in the same place either way -- not because
    // the two orders are required to agree.
    #[error("no such verification flow")]
    UnknownFlow,
    #[error("the flow is not at a stage where this call applies")]
    WrongStage,
    #[error("the short authentication string is not available yet")]
    MaterialNotReady,
    #[error("no such device")]
    UnknownDevice,
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
            matrix_crypto_core::MachineError::UnknownFlow => Self::UnknownFlow,
            matrix_crypto_core::MachineError::WrongStage => Self::WrongStage,
            matrix_crypto_core::MachineError::MaterialNotReady => Self::MaterialNotReady,
            matrix_crypto_core::MachineError::UnknownDevice => Self::UnknownDevice,
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

/// How far along one verification flow is. Mirror of the core's
/// `FlowStage`, carrying the UniFFI enum derive.
///
/// **A new variant is appended here. It is never inserted, and no existing
/// one is ever removed or reordered.** This is the same rule
/// `SessionFfiError` below states for errors, and it applies to an enum
/// from birth rather than from its first change: UniFFI assigns each
/// variant's wire ordinal by declaration position, and the generated
/// TypeScript reads that back as a numbered `switch` in exactly this order.
/// Inserting a variant renumbers every variant after it, so a binding
/// generated before the insert does not fail on the new value -- it decodes
/// every later value as its neighbour, and a caller is told the flow is at
/// a stage it is not. For a stage enum specifically, the worst
/// misdecoding available is `Cancelled` read as `Done`, which is a refused
/// verification presented as a successful one.
///
/// **This comment ships.** Codegen copies it verbatim into
/// `src/generated/matrix_crypto.ts`, so it has to describe the rule rather
/// than the state of one commit.
///
/// The core's own `FlowStage` documents what each stage means for a person
/// looking at a screen; this mirror deliberately repeats none of it, so the
/// two cannot drift into saying different things. The `From` impl below is
/// exhaustive, so a variant added to either side fails this build.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum VerificationStage {
    Requested,
    Ready,
    Started,
    KeysExchanged,
    Confirmed,
    Done,
    Cancelled,
}

impl From<matrix_crypto_core::FlowStage> for VerificationStage {
    fn from(value: matrix_crypto_core::FlowStage) -> Self {
        // Exhaustive, no wildcard arm. See Global Constraints.
        match value {
            matrix_crypto_core::FlowStage::Requested => Self::Requested,
            matrix_crypto_core::FlowStage::Ready => Self::Ready,
            matrix_crypto_core::FlowStage::Started => Self::Started,
            matrix_crypto_core::FlowStage::KeysExchanged => Self::KeysExchanged,
            matrix_crypto_core::FlowStage::Confirmed => Self::Confirmed,
            matrix_crypto_core::FlowStage::Done => Self::Done,
            matrix_crypto_core::FlowStage::Cancelled => Self::Cancelled,
        }
    }
}

/// One symbol of a short authentication string. Mirror of the core's
/// `SasEmoji`, carrying the UniFFI record derive.
///
/// No `Debug` derive, and the reason is stronger here than anywhere else in
/// this file: this record *is* the authentication material. Anything that
/// learns it while a flow is open learns what an interposed party would
/// need to answer the comparison correctly. The core hand-writes a
/// redacting `Debug` for its own copy; this mirror carries none at all,
/// the same choice `Envelope` and `CryptoMachineConfig` above already make.
#[derive(Clone, uniffi::Record)]
pub struct SasEmoji {
    pub symbol: String,
    pub description: String,
}

/// The short authentication string, in both forms the protocol can
/// produce. Mirror of the core's `SasMaterial`.
///
/// No `Debug` derive. See `SasEmoji` above: one symbol is a seventh of the
/// answer, and the decimals are the whole of it.
#[derive(Clone, uniffi::Record)]
pub struct SasMaterial {
    pub emoji: Option<Vec<SasEmoji>>,
    /// A three-element tuple in the core; three named fields here, because
    /// UniFFI has no tuple type and a `Vec<u16>` would let a length other
    /// than three cross the boundary and be discovered by a consumer
    /// indexing past the end.
    pub decimal_one: u16,
    pub decimal_two: u16,
    pub decimal_three: u16,
}

impl From<matrix_crypto_core::SasMaterial> for SasMaterial {
    fn from(value: matrix_crypto_core::SasMaterial) -> Self {
        // Destructured, not field-accessed: a field added to the core
        // record later must fail this build rather than be silently
        // dropped. See Global Constraints.
        let matrix_crypto_core::SasMaterial { emoji, decimals } = value;
        let (decimal_one, decimal_two, decimal_three) = decimals;
        Self {
            emoji: emoji.map(|symbols| {
                symbols
                    .into_iter()
                    .map(|symbol| {
                        let matrix_crypto_core::SasEmoji {
                            symbol,
                            description,
                        } = symbol;
                        SasEmoji {
                            symbol,
                            description,
                        }
                    })
                    .collect()
            }),
            decimal_one,
            decimal_two,
            decimal_three,
        }
    }
}

/// What this library will say about one device. Mirror of the core's
/// `TrustState`.
///
/// The append-only ordinal rule `VerificationStage` above states in full
/// applies to this enum too, and with a sharper consequence: the values are
/// ordered least-trusted first, so a renumbering shifts every answer one
/// place towards `Verified`.
///
/// `Recognized` is not produced by this build. It is declared because the
/// TypeScript union it mirrors is closed, and widening a closed union later
/// is a breaking change for every consumer that switched on it
/// exhaustively. The core's own `TrustState` says so at the variant.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum TrustState {
    Unverified,
    Recognized,
    Verified,
}

impl From<matrix_crypto_core::TrustState> for TrustState {
    fn from(value: matrix_crypto_core::TrustState) -> Self {
        // Exhaustive, no wildcard arm. See Global Constraints.
        match value {
            matrix_crypto_core::TrustState::Unverified => Self::Unverified,
            matrix_crypto_core::TrustState::Recognized => Self::Recognized,
            matrix_crypto_core::TrustState::Verified => Self::Verified,
        }
    }
}

/// One device of one user, and the trust this library reports for it.
/// Mirror of the core's `DeviceStatus`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceStatus {
    pub device_id: String,
    pub trust: TrustState,
}

impl From<matrix_crypto_core::DeviceStatus> for DeviceStatus {
    fn from(value: matrix_crypto_core::DeviceStatus) -> Self {
        // Destructured, not field-accessed. See Global Constraints.
        let matrix_crypto_core::DeviceStatus { device_id, trust } = value;
        Self {
            device_id,
            trust: trust.into(),
        }
    }
}

/// Every device this machine knows of for `user_id`, with its trust.
/// Mirrors `device_statuses`; see its own doc comment in
/// `matrix-crypto-core::identity`, including why an empty answer does not
/// mean the user has no devices.
#[uniffi::export]
pub async fn device_statuses(user_id: String) -> Result<Vec<DeviceStatus>, MachineFfiError> {
    matrix_crypto_core::device_statuses(&user_id)
        .await
        .map(|statuses| statuses.into_iter().map(Into::into).collect())
        .map_err(Into::into)
}

/// Asks a device to verify itself against this one, returning the opaque
/// identifier every other call below addresses the flow by. Mirrors
/// `request_flow`; see its own doc comment in
/// `matrix-crypto-core::verification`.
#[uniffi::export]
pub async fn request_verification(
    user_id: String,
    device_id: String,
) -> Result<String, MachineFfiError> {
    matrix_crypto_core::request_flow(&user_id, &device_id)
        .await
        .map(|flow| {
            // Destructured, not field-accessed. See Global Constraints.
            let matrix_crypto_core::FlowId(id) = flow;
            id
        })
        .map_err(Into::into)
}

/// Agrees to a verification the other side asked for. Mirrors
/// `accept_flow`.
#[uniffi::export]
pub async fn accept_verification(verification_id: String) -> Result<(), MachineFfiError> {
    matrix_crypto_core::accept_flow(&matrix_crypto_core::FlowId(verification_id))
        .await
        .map_err(Into::into)
}

/// Starts the comparison itself, once both sides are ready. Mirrors
/// `begin_comparison`; see its own doc comment for the two conditions its
/// `WrongStage` folds together, and the facade for how they are told apart
/// again.
#[uniffi::export]
pub async fn start_verification_comparison(verification_id: String) -> Result<(), MachineFfiError> {
    matrix_crypto_core::begin_comparison(&matrix_crypto_core::FlowId(verification_id))
        .await
        .map_err(Into::into)
}

/// How far along the flow is. Mirrors `flow_stage`.
#[uniffi::export]
pub async fn verification_stage(
    verification_id: String,
) -> Result<VerificationStage, MachineFfiError> {
    matrix_crypto_core::flow_stage(&matrix_crypto_core::FlowId(verification_id))
        .await
        .map(Into::into)
        .map_err(Into::into)
}

/// The short authentication string, once there is one. Mirrors
/// `read_material`; see its own doc comment for why the absence of a string
/// is two different errors and not an empty record.
#[uniffi::export]
pub async fn verification_material(
    verification_id: String,
) -> Result<SasMaterial, MachineFfiError> {
    matrix_crypto_core::read_material(&matrix_crypto_core::FlowId(verification_id))
        .await
        .map(Into::into)
        .map_err(Into::into)
}

/// Says the strings matched. Mirrors `confirm_flow`.
#[uniffi::export]
pub async fn confirm_verification(verification_id: String) -> Result<(), MachineFfiError> {
    matrix_crypto_core::confirm_flow(&matrix_crypto_core::FlowId(verification_id))
        .await
        .map_err(Into::into)
}

/// Refuses the verification, or abandons it. Mirrors `cancel_flow`.
#[uniffi::export]
pub async fn cancel_verification(verification_id: String) -> Result<(), MachineFfiError> {
    matrix_crypto_core::cancel_flow(&matrix_crypto_core::FlowId(verification_id))
        .await
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

/// What upstream knew about the sender of one decrypted event. Mirror of
/// the core's `SenderVerification`.
///
/// The append-only ordinal rule `VerificationStage` above states in full
/// applies to this enum too. **Do not borrow `TrustState`'s wording for it.**
/// That enum is ordered least-trusted-*first*, so an insertion shifts every
/// answer one place towards `Verified`; this one is ordered
/// most-authentic-first, so the direction inverts and the sentence becomes
/// false. It was borrowed anyway when this enum was written, and review
/// caught it.
///
/// Worked through, with a variant inserted at position 1: new bindings send
/// `UnsignedDevice` as 5, and a stale binding reads 5 as
/// `NoDeviceMissing` -- one place *away* from `Verified`, which is
/// the fail-safe direction. Every shifted value moves that way, because
/// `Verified` holds the lowest ordinal and nothing can shift towards it.
///
/// **The hazard that does follow from `Verified` being first is the
/// inserted variant itself: it takes ordinal 1, and every stale binding
/// decodes it as `Verified`.** An unknown state -- whatever a later
/// milestone adds -- would be presented to a product as the one value that
/// guarantees authenticity, which is the worst sentence this library can
/// say and the reason this enum is called out separately at all. Appending
/// costs an unrecognised ordinal instead: the generated converter's
/// `default:` arm throws `UnexpectedEnumCase`, which is a clean failure.
/// Append; never insert; and never reorder, which would move a value *to*
/// position 1 by a different route.
///
/// The order itself is not this crate's choice and is not the core's
/// either -- both take it from upstream's own `VerificationState` and
/// `VerificationLevel` declarations, so the three lists can be read side by
/// side. The core's own enum documents what each value means, and which
/// three of them this build cannot produce; this mirror deliberately
/// repeats none of it, so the two cannot drift into saying different
/// things.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum SenderVerification {
    Verified,
    UnverifiedIdentity,
    VerificationViolation,
    UnsignedDevice,
    NoDeviceMissing,
    NoDeviceInsecureSource,
    MismatchedSender,
}

impl From<matrix_crypto_core::SenderVerification> for SenderVerification {
    fn from(value: matrix_crypto_core::SenderVerification) -> Self {
        // Exhaustive, no wildcard arm. See Global Constraints.
        match value {
            matrix_crypto_core::SenderVerification::Verified => Self::Verified,
            matrix_crypto_core::SenderVerification::UnverifiedIdentity => Self::UnverifiedIdentity,
            matrix_crypto_core::SenderVerification::VerificationViolation => {
                Self::VerificationViolation
            }
            matrix_crypto_core::SenderVerification::UnsignedDevice => Self::UnsignedDevice,
            matrix_crypto_core::SenderVerification::NoDeviceMissing => Self::NoDeviceMissing,
            matrix_crypto_core::SenderVerification::NoDeviceInsecureSource => {
                Self::NoDeviceInsecureSource
            }
            matrix_crypto_core::SenderVerification::MismatchedSender => Self::MismatchedSender,
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
    /// `None` from `encrypt_event`, `Some` from every successful
    /// `decrypt_event`. The core's own field says why, at length; this
    /// mirror does not repeat it.
    pub sender_verification: Option<SenderVerification>,
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
            sender_verification,
        } = value;
        Self {
            scope,
            algorithm,
            event_type,
            ciphertext,
            sender,
            sender_verification: sender_verification.map(Into::into),
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
///
/// **A new variant is appended here. It is never inserted.** UniFFI assigns
/// each variant's wire ordinal by declaration position, which
/// `FfiConverterTypeSessionFfiError.readFromCursor` in the generated
/// TypeScript reads back as a numbered `switch` in exactly this order. So
/// inserting a variant renumbers every variant after it, and any binding
/// generated before that insert misdecodes all of them rather than failing
/// cleanly on the one that was added. Appending costs one unrecognised
/// ordinal instead, which is why `SessionRefused` sits last, after
/// `Undecryptable`, rather than beside `UnsharedSession` where it reads
/// more naturally, and why `MalformedIdentifier` sits after that rather
/// than beside `MalformedPayload`. The core's own `SessionError` does put
/// each of them where it reads, because that enum crosses no boundary and
/// its order is free; these two lists are deliberately not in the same
/// order, and the `From` impl below is exhaustive so neither can drift
/// silently.
///
/// **This comment ships.** Codegen copies it verbatim into
/// `src/generated/matrix_crypto.ts`, twice, so it has to describe the rule
/// rather than the state of one commit. It used to end by saying the
/// committed bindings "still only know cases 1 through 8", because the
/// change that added `SessionRefused` deliberately did not regenerate them.
/// The regeneration ran a commit later, and that sentence went on shipping
/// to consumers, sitting directly above `case 9`. `gate:drift` cannot catch
/// that class of defect at all: the generated file reproduces its source
/// faithfully, and it is the content of the source that expired.
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
    #[error("the session that encrypted this event was refused by its sender's policy")]
    SessionRefused,
    #[error("an identifier could not be parsed")]
    MalformedIdentifier,
}

impl From<matrix_crypto_core::SessionError> for SessionFfiError {
    fn from(e: matrix_crypto_core::SessionError) -> Self {
        // Exhaustive, no wildcard arm. See Global Constraints.
        match e {
            matrix_crypto_core::SessionError::MalformedPayload => Self::MalformedPayload,
            matrix_crypto_core::SessionError::MalformedIdentifier => Self::MalformedIdentifier,
            matrix_crypto_core::SessionError::NotInitialised => Self::NotInitialised,
            matrix_crypto_core::SessionError::Failed => Self::Failed,
            matrix_crypto_core::SessionError::UnknownRequest => Self::UnknownRequest,
            matrix_crypto_core::SessionError::MissingKey => Self::MissingKey,
            matrix_crypto_core::SessionError::UnsharedSession => Self::UnsharedSession,
            matrix_crypto_core::SessionError::SessionRefused => Self::SessionRefused,
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

/// Mirror of the core's `CryptoSignal`, carrying the UniFFI enum derive.
///
/// **Appended after every other declaration in this file, deliberately.**
/// UniFFI assigns wire ordinals by declaration position, so a type or a
/// variant inserted above an existing one renumbers it and makes stale
/// bindings decode the wrong value. New declarations go last, always.
///
/// `verification_id` rather than the core's `flow_id`: the published
/// TypeScript surface calls this identifier a `verificationId` at every
/// call that takes one, and a signal that named it something else would be
/// asking a product to work out that the two are the same value.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum CryptoSignal {
    TrustChanged {
        user: String,
        state: TrustState,
    },
    VerificationRequested {
        user: String,
        device_id: String,
        verification_id: String,
    },
}

/// A `From` impl rather than a match buried in the adapter below, for the
/// reason `tests/value_mapping.rs` states at length: `VerificationRequested`
/// carries three `String` fields, so swapping any two of them compiles,
/// passes `clippy -D warnings`, and passes every other test in this
/// repository. Public and stateless, so that file can pin it.
impl From<matrix_crypto_core::CryptoSignal> for CryptoSignal {
    fn from(value: matrix_crypto_core::CryptoSignal) -> Self {
        // Destructured and matched exhaustively, with no wildcard arm: a
        // variant or a field the core adds later must fail to compile here
        // rather than be silently dropped. See Global Constraints.
        match value {
            matrix_crypto_core::CryptoSignal::TrustChanged { user, state } => Self::TrustChanged {
                user,
                state: state.into(),
            },
            matrix_crypto_core::CryptoSignal::VerificationRequested {
                user,
                device_id,
                flow_id,
            } => Self::VerificationRequested {
                user,
                device_id,
                verification_id: flow_id,
            },
        }
    }
}

/// `with_foreign` makes this implementable from JavaScript, like
/// `ProbeObserver`. Unlike `ProbeObserver`, it is registered once for the
/// process rather than handed to one call.
#[uniffi::export(with_foreign)]
pub trait CryptoObserver: Send + Sync {
    fn on_signal(&self, signal: CryptoSignal);
}

/// Translation only, exactly like `ObserverAdapter`: by the time this runs,
/// the core has already detached the call onto a thread of the library's
/// own, off whatever stack and whatever lock produced the signal.
struct CryptoObserverAdapter(Arc<dyn CryptoObserver>);

impl matrix_crypto_core::CryptoObserver for CryptoObserverAdapter {
    fn on_signal(&self, signal: matrix_crypto_core::CryptoSignal) {
        self.0.on_signal(signal.into());
    }
}

/// Registers the process's crypto signal observer, replacing any previous
/// one. Mirrors `set_crypto_observer`; see its own doc comment in
/// `matrix-crypto-core::observer`, including why this is not a call a
/// product ever makes for itself.
///
/// Synchronous on purpose. `onCryptoSignal` in the TypeScript facade is a
/// synchronous subscribe that returns an unsubscribe function, and it calls
/// this on the first subscription; an async export here would force it to
/// leave a promise unawaited on the one path that must not fail quietly.
#[uniffi::export]
pub fn set_crypto_observer(observer: Arc<dyn CryptoObserver>) {
    matrix_crypto_core::set_crypto_observer(Arc::new(CryptoObserverAdapter(observer)));
}

/// Forgets the registered crypto signal observer. Mirrors
/// `clear_crypto_observer`; see its own doc comment in
/// `matrix-crypto-core::observer` for why the last unsubscribe must call
/// this rather than merely dropping its listener.
///
/// Appended after `set_crypto_observer`, which is after everything else in
/// this file, for the ordinal reason `CryptoSignal`'s own comment gives.
/// Synchronous for the same reason its counterpart is: the TypeScript
/// unsubscribe is a synchronous closure and must not leave a promise
/// unawaited on the one path that must not fail quietly.
#[uniffi::export]
pub fn clear_crypto_observer() {
    matrix_crypto_core::clear_crypto_observer();
}
