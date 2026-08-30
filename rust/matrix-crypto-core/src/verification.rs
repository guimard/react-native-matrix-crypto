//! Verifying another device by comparing a short authentication string.
//!
//! Two people who can talk to each other out of band read a seven-symbol
//! string off their screens and say whether it matches. If it does, each
//! side's device is proven to be the one holding the key it claims, and the
//! library records the other's device as verified. If it does not, the flow
//! is cancelled and nothing is recorded. That refusal is the entire point:
//! a comparison that can only ever agree proves nothing.
//!
//! # Flows are addressed by identifier, not by handle
//!
//! Upstream's verification API is handle-shaped -- a request and a
//! comparison are both objects with state that the caller holds. This
//! library's ownership model is not: `create_machine` returns nothing, the
//! machine lives here, and no handle crosses the boundary. So a flow is
//! named by an opaque identifier and the handles behind it live in this
//! module's own registry, which is the cost that decision carries and which
//! the outbound request pump in `session.rs` already paid once. Its
//! registry is the worked precedent for this one: key by the thing upstream
//! keys by, evict on a documented rule with upstream evidence, keep an
//! entry a failed call could still want, and be able to show the map does
//! not grow without bound.
//!
//! # Why the handles are held rather than looked up each time
//!
//! Upstream keeps its own map of live flows, and a lookup against it would
//! need no registry here at all. It cannot be used for this, because
//! upstream drops a flow from that map as soon as the flow is done or
//! cancelled -- `VerificationMachine::garbage_collect`, run at the top of
//! every `receive_sync_changes`. A caller that asked "what happened to my
//! verification?" one sync too late would be told the flow never existed,
//! which is the wrong answer to the most important question in this module.
//! Upstream's own callers survive that because they hold the handle: the
//! handle and the map entry share one observable state, and dropping the
//! map entry does not disturb the handle. So this registry holds handles,
//! and a finished flow keeps reporting how it finished.
//!
//! # What the registry does with a finished flow
//!
//! It releases it the next time a flow is registered, which is upstream's
//! own rule (`retain(|_, v| !(v.is_done() || v.is_cancelled()))`) moved
//! from "on the next sync" to "on the next registration". A caller can
//! therefore read a cancelled or completed flow's outcome for as long as it
//! takes to start another one, and no longer. The registry holds at most
//! the flows that are still live plus those that finished since the last
//! registration, which is bounded by how many a caller runs at once; it
//! does not accumulate one entry per verification ever attempted.
//! `a_finished_flow_is_not_retained_forever` in `tests/sas_two_party.rs` is
//! the proof, and it is the same shape as the pump's own
//! `a_stale_keys_upload_id_does_not_accumulate_across_repeated_calls`.
//!
//! # Two shapes of flow, and one surface over both
//!
//! A verification normally opens with an `m.key.verification.request`: one
//! side invites, the other agrees, and only then does either start the
//! comparison. That is the shape this library sends, and it was the only
//! one this module could answer until `091988f`. It is not the only one now
//! -- see "Every call on this surface answers both" below, which is the
//! current statement and which the sentence this replaces contradicted.
//!
//! The Matrix protocol also still carries the shape MSC3122 deprecated --
//! a bare `m.key.verification.start` with no request before it, to-device
//! only. It is not a legacy curiosity: it is what some third-party clients
//! implement and *all* they implement, `matrix-nio` among them, and
//! `matrix-sdk-crypto` 0.18.0 both emits it (`Device::start_verification`)
//! and accepts it (`verification/machine.rs:430-450`). A flow that arrives
//! that way exists inside upstream's machine as a comparison and nothing
//! else -- there is no request object behind it and there never will be.
//!
//! Every call on this surface answers both, and a caller does not have to
//! know which it has: [`accept_flow`] agrees to whatever the flow is
//! waiting on, [`read_material`] shows the string, [`confirm_flow`] says it
//! matched, [`cancel_flow`] refuses. The one visible difference is that a
//! bare-start flow is never [`FlowStage::Ready`] -- it is a comparison from
//! the moment it exists -- so [`begin_comparison`] has nothing to do on one
//! and says so.
//!
//! The two shapes differ in *how many times* a caller agrees, not in what
//! agreeing means: a request-shaped flow can need [`accept_flow`] twice,
//! once for the invitation and once more if the peer opens the comparison
//! rather than waiting for this side to. See that function for why, and
//! for the silent stall that used to be.
//!
//! # Requests
//!
//! Every call here that produces a message hands it to
//! `session::queue_action_request`, because upstream does not queue the
//! messages it returns to its caller -- see that function's own doc
//! comment. They then leave through `take_outgoing_requests` and are
//! resolved through `mark_request_sent` like every other request this
//! library produces. That is not optional bookkeeping: upstream advances
//! the comparison from "accepted" to "keys exchanged" only when the key
//! message is reported sent, so a caller that never resolves what it
//! drained never sees a short authentication string at all. That failure is
//! named rather than silent -- see [`MachineError::MaterialNotReady`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex as StdMutex;

use matrix_sdk_common::deserialized_responses::ProcessedToDeviceEvent;
use matrix_sdk_common::ruma::events::key::verification::VerificationMethod;
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId};
use matrix_sdk_crypto::types::requests::OutgoingRequest as UpstreamOutgoingRequest;
use matrix_sdk_crypto::{
    Sas, SasState, Verification, VerificationRequest, VerificationRequestState,
};

use crate::identity::TrustState;
use crate::machine::{with_machine, MachineError};
use crate::observer::CryptoSignal;

/// The opaque name of one verification flow.
///
/// Upstream's own identifier for the flow, which is the transaction id both
/// sides already carry in every message they exchange about it. Opaque on
/// this surface: nothing outside this module may parse it, and the only
/// thing a caller may do with one is hand it back.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowId(pub String);

/// One symbol of a short authentication string, with the word for it.
///
/// `description` is upstream's own English word for the symbol. A product
/// showing these to a user in another language looks the word up from the
/// symbol's position, which is why both sides of the pair travel together.
#[derive(Clone, PartialEq, Eq)]
pub struct SasEmoji {
    pub symbol: String,
    pub description: String,
}

/// The short authentication string, in both of the forms the protocol can
/// produce.
///
/// `emoji` is optional and `decimals` is not, and that asymmetry is
/// upstream's, not a convenience: the symbol form is only produced when
/// both sides negotiated it, and a surface offering only symbols therefore
/// has a live path with nothing to show. The digits are always there once
/// the keys are exchanged.
///
/// A caller must show one of these to a person and ask whether it matches
/// what the other person sees. Comparing them programmatically across a
/// channel the flow itself established would prove nothing -- the channel is
/// what is being verified.
#[derive(Clone, PartialEq, Eq)]
pub struct SasMaterial {
    pub emoji: Option<Vec<SasEmoji>>,
    pub decimals: (u16, u16, u16),
}

/// A hand-written, redacting `Debug`, like `MachineConfig`'s and
/// `Envelope`'s and for the same reason: this record *is* the
/// authentication material. Anything that learns it while a flow is open
/// learns what an interposed party would need to answer the comparison
/// correctly, so it must never reach a log line, a panic message or an
/// error's `Display`. Destructured rather than field-accessed, so a field
/// added later fails this to compile instead of being printed in full.
impl std::fmt::Debug for SasMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let SasMaterial { emoji, decimals: _ } = self;
        f.debug_struct("SasMaterial")
            .field("emoji_count", &emoji.as_ref().map(Vec::len))
            .field("decimals", &"[redacted]")
            .finish()
    }
}

/// See `SasMaterial`'s own `Debug`: one symbol is a seventh of the answer.
impl std::fmt::Debug for SasEmoji {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let SasEmoji {
            symbol: _,
            description: _,
        } = self;
        f.debug_struct("SasEmoji")
            .field("symbol", &"[redacted]")
            .finish()
    }
}

/// How far along a flow is.
///
/// Deliberately coarser than upstream's two state enums, which between them
/// distinguish nineteen states. What a caller has to decide is which of a
/// small set of things to do next -- wait, accept, show the string, or tell
/// the user it is over -- and every distinction upstream draws that does not
/// change that answer is one this surface would be inviting a product to
/// branch on for no reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowStage {
    /// Asked for, by one side or the other, and not yet answered.
    Requested,
    /// Both sides have agreed to verify and one of them may now start the
    /// comparison.
    Ready,
    /// The comparison has started; the keys are not exchanged yet, so there
    /// is nothing to show.
    Started,
    /// The short authentication string is available and waiting to be
    /// compared.
    KeysExchanged,
    /// This side has said the strings match; the other side has not yet.
    Confirmed,
    /// Both sides said the strings match. The other device is now verified.
    Done,
    /// Over without a verification, whether because a side refused, a side
    /// abandoned it, or it timed out.
    Cancelled,
}

/// One flow this process is taking part in.
///
/// The comparison handle is cached rather than stored at registration
/// because it does not exist yet at registration: a flow becomes a
/// comparison later, when one side starts one. It is filled in from the
/// request handle, which carries it once that has happened, so no separate
/// lookup against upstream's own map is needed -- and would not survive that
/// map's garbage collection anyway.
struct FlowRecord {
    /// The request handle, for a flow that began with one.
    ///
    /// `None` for a flow that began as a bare `m.key.verification.start`
    /// with no `m.key.verification.request` before it. That is the shape
    /// MSC3122 deprecated, and upstream still both emits it
    /// (`identities/device.rs`'s `Device::start_verification`) and accepts
    /// it (`verification/machine.rs:430-450`), where it builds the
    /// comparison straight from the start event and writes **nothing** to
    /// the map `get_verification_request` reads. So such a flow has no
    /// request behind it and never will. It is also the only shape some
    /// third-party clients speak, which is what this option is here for;
    /// see the module header's own section on it.
    request: Option<VerificationRequest>,
    comparison: Option<Sas>,
    /// Whether this flow's completion has already been announced on the
    /// crypto signal channel.
    ///
    /// A flow reaches [`FlowStage::Done`] once and is announced once, but
    /// the two moments that can notice it -- the confirmation that finished
    /// it, and the next sync -- can both fire for the same flow. Without
    /// this, whichever ran second would emit a duplicate `TrustChanged`.
    /// Eviction is not a substitute: `release_finished` runs on the next
    /// registration, which is later than both.
    completion_announced: bool,
}

impl FlowRecord {
    /// A flow that began with an `m.key.verification.request`.
    fn from_request(request: VerificationRequest) -> Self {
        FlowRecord {
            request: Some(request),
            comparison: None,
            completion_announced: false,
        }
    }

    /// A flow that began as a bare `m.key.verification.start`, registered
    /// with the comparison it produced.
    ///
    /// These two constructors are the only way a record is built, and
    /// between them they keep this module's one structural invariant:
    /// **every record holds at least one handle.** Neither field is ever
    /// set back to `None` afterwards, so a record keeps whichever it was
    /// built with for the life of the entry, and every function below can
    /// say truthfully which shape it is looking at.
    fn from_comparison(comparison: Sas) -> Self {
        FlowRecord {
            request: None,
            comparison: Some(comparison),
            completion_announced: false,
        }
    }
}

/// Process-wide registry of the flows this library is taking part in.
///
/// A `std::sync::Mutex`, not `tokio::sync::Mutex`, and for the same reason
/// `session.rs`'s request registry is: every critical section below is a
/// plain synchronous map operation with no `.await` inside it. The handles
/// are cloned out from under the lock and the slow, fallible work is done
/// on the clones, which is safe because a clone and its original share one
/// observable state -- that is the property this whole module rests on.
static FLOWS: StdMutex<BTreeMap<String, FlowRecord>> = StdMutex::new(BTreeMap::new());

/// Empties the registry, so a test that registered a flow does not leave a
/// handle -- and through it an `Arc` on the crypto store -- alive past the
/// machine it belongs to. Called from `machine::reset_for_test`, and called
/// there *before* the store is dropped, for the reason that function's own
/// comment gives.
#[cfg(test)]
pub(crate) fn reset_flows_for_test() {
    FLOWS
        .lock()
        .expect("verification registry poisoned")
        .clear();
}

#[cfg(test)]
fn flow_count() -> usize {
    FLOWS.lock().expect("verification registry poisoned").len()
}

/// Errors must not carry an identifier or key material, so an upstream
/// store failure reports its shape and nothing else -- the same rule, and
/// the same fixed string, as `machine.rs`'s `store_error_detail`.
fn store_failed() -> MachineError {
    MachineError::Store {
        detail: "the crypto store could not be opened".to_string(),
    }
}

/// The handles for one flow, cloned out of the registry.
///
/// Cloned, not borrowed: two of the calls below are `async` and must not
/// hold a lock across an `.await`. A cloned handle is not a snapshot -- it
/// observes the same state the registry's copy does -- so nothing read
/// through one of these is stale by the time it is read.
struct Handles {
    /// `None` exactly when the flow began as a bare
    /// `m.key.verification.start` -- see [`FlowRecord::request`].
    request: Option<VerificationRequest>,
    comparison: Option<Sas>,
}

/// Fills in a record's comparison handle if the flow has become one, and
/// returns it.
///
/// Read from the request handle rather than looked up in upstream's map:
/// the request carries the comparison once one has started, on both the
/// side that started it and the side that received the start, and unlike
/// the map it is not garbage-collected out from under us.
fn comparison_of(record: &mut FlowRecord) -> Option<&Sas> {
    if record.comparison.is_none() {
        // Only a request-shaped record can reach here with nothing cached:
        // a request-less one is registered with its comparison already in
        // hand and never loses it.
        if let Some(VerificationRequestState::Transitioned { verification, .. }) =
            record.request.as_ref().map(VerificationRequest::state)
        {
            record.comparison = verification.sas_v1().map(|boxed| *boxed);
        }
    }
    record.comparison.as_ref()
}

fn stage_of(record: &mut FlowRecord) -> FlowStage {
    if let Some(comparison) = comparison_of(record) {
        return stage_of_comparison(comparison);
    }
    let Some(request) = record.request.as_ref() else {
        // Neither handle. Not reachable through either of `FlowRecord`'s
        // two constructors -- one supplies a request, the other supplies a
        // comparison, and nothing sets either back to `None` -- so this
        // arm keeps the function total rather than describing a flow
        // anything can produce. `Cancelled` is the one stage that cannot
        // mislead a caller into acting on it: it says "there is nothing
        // further to do here", which is exactly true of a flow with no
        // handle behind it. Named rather than left to a fallthrough, which
        // is the class this crate closed in `ecfd293`.
        return FlowStage::Cancelled;
    };
    // Exhaustive, no wildcard, like every other upstream match in this
    // crate: a state upstream adds later must fail this build rather than
    // be reported as whichever stage a wildcard happened to name.
    match request.state() {
        VerificationRequestState::Created { .. } | VerificationRequestState::Requested { .. } => {
            FlowStage::Requested
        }
        VerificationRequestState::Ready { .. } => FlowStage::Ready,
        // Unreachable: `comparison_of` above returns `Some` for exactly
        // this state, and returned before this match if it did. Mapped
        // truthfully anyway rather than left to a wildcard.
        VerificationRequestState::Transitioned { .. } => FlowStage::Started,
        VerificationRequestState::Done => FlowStage::Done,
        VerificationRequestState::Cancelled(_) => FlowStage::Cancelled,
    }
}

fn stage_of_comparison(comparison: &Sas) -> FlowStage {
    match comparison.state() {
        // Three upstream states, one stage: the comparison exists and has
        // nothing to show yet. Upstream's own public projection already
        // folds three more of its internal states into `Accepted` here.
        SasState::Created { .. } | SasState::Started { .. } | SasState::Accepted { .. } => {
            FlowStage::Started
        }
        SasState::KeysExchanged { .. } => FlowStage::KeysExchanged,
        SasState::Confirmed => FlowStage::Confirmed,
        SasState::Done { .. } => FlowStage::Done,
        SasState::Cancelled(_) => FlowStage::Cancelled,
    }
}

/// The stage a set of already-fetched handles describes.
///
/// Separate from [`stage_of`], which takes the registry's own record and can
/// fill its comparison cache in passing; this one reads handles that have
/// already been cloned out, which is what every public call below holds.
fn stage_from(handles: &Handles) -> FlowStage {
    let mut record = FlowRecord {
        request: handles.request.clone(),
        comparison: handles.comparison.clone(),
        completion_announced: false,
    };
    stage_of(&mut record)
}

fn is_finished(stage: FlowStage) -> bool {
    matches!(stage, FlowStage::Done | FlowStage::Cancelled)
}

/// Drops every flow that has finished, except one whose completion nobody
/// has collected yet.
///
/// Upstream's own rule, `retain(|_, v| !(v.is_done() || v.is_cancelled()))`
/// from `VerificationMachine::garbage_collect`, run here at the one moment
/// this registry can grow rather than on every sync. See the module's own
/// header for what that costs a caller and why it is bounded.
///
/// # The one exception, and why it does not reopen the growth question
///
/// Sweeping is not serialised against announcing. A comparison reaches
/// `Done` inside `receive_sync_changes`, and `announce_state_changes` runs
/// after that call has released the machine lock; any concurrent call that
/// reaches [`handles`] -> [`register`] in that window sweeps, and an
/// unconditional sweep would drop the record before
/// [`take_pending_completions`] had ever seen it. The `TrustChanged` would
/// be lost with nothing reporting it.
///
/// So a `Done` record whose completion has not been taken survives one more
/// pass. Three properties keep that from becoming unbounded retention:
///
/// * only `Done` is exempt. A `Cancelled` flow has no completion to
///   announce and is always swept, which is what
///   `a_finished_flow_is_not_retained_forever` measures.
/// * the exemption ends at the next sync. `take_pending_completions` marks
///   every `Done` record it inspects, whether or not it produced a signal,
///   so the record is sweepable from then on.
/// * with no observer registered, nothing will ever announce, so nothing is
///   exempt. That is also what keeps a process that never subscribes on
///   exactly the retention behaviour it had before this existed.
fn release_finished(flows: &mut BTreeMap<String, FlowRecord>) {
    // Read once, outside the loop: it takes the observer registry's read
    // lock, and this already holds the flow registry's. Nothing anywhere
    // takes those two in the other order.
    let something_will_announce = crate::observer::crypto_observer().is_some();
    flows.retain(|_, record| {
        let stage = stage_of(record);
        if !is_finished(stage) {
            return true;
        }
        stage == FlowStage::Done && !record.completion_announced && something_will_announce
    });
}

fn cached(flow_id: &str) -> Option<Handles> {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    let record = flows.get_mut(flow_id)?;
    let comparison = comparison_of(record).cloned();
    Some(Handles {
        request: record.request.clone(),
        comparison,
    })
}

fn register(flow_id: &str, record: FlowRecord) -> Handles {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    release_finished(&mut flows);
    let record = flows.entry(flow_id.to_string()).or_insert(record);
    let comparison = comparison_of(record).cloned();
    Handles {
        request: record.request.clone(),
        comparison,
    }
}

/// The identifier upstream itself gives the flow behind a record.
///
/// Read back off the handle rather than taken from whatever string the
/// caller passed, so the registry is keyed by exactly what upstream keys
/// by. `None` only for a record holding neither handle, which
/// [`FlowRecord`]'s two constructors cannot produce.
fn upstream_flow_id(record: &FlowRecord) -> Option<String> {
    if let Some(request) = &record.request {
        return Some(request.flow_id().as_str().to_string());
    }
    record
        .comparison
        .as_ref()
        .map(|comparison| comparison.flow_id().as_str().to_string())
}

/// Registers `request` under `flow_id` if the registry does not already
/// hold that flow, and reports whether it did.
///
/// Separate from [`register`] because the announcement path needs the
/// insertion and the "was it new?" question answered under one lock. Split
/// into a `contains_key` and a `register`, an inbound flow could be
/// announced twice by two syncs that interleaved between them.
///
/// Sweeps before it asks, which is [`register`]'s order rather than the
/// reverse. The two disagreed until a review noticed: asking first meant a
/// finished record still sitting in the registry would refuse an identifier
/// that reused its name. Matrix transaction ids are not reused, so nothing
/// observable changes -- but two functions doing the same two things in
/// opposite orders is a question a reader has to answer, and it costs
/// nothing not to ask it.
fn register_if_absent(flow_id: &str, record: FlowRecord) -> bool {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    release_finished(&mut flows);
    if flows.contains_key(flow_id) {
        return false;
    }
    flows.insert(flow_id.to_string(), record);
    true
}

/// Releases a flow the announcement pass registered and could not
/// announce, so the next pass can find it again.
///
/// The exact undo of [`register_if_absent`]'s insertion, and only legal
/// against a flow this same pass inserted -- see [`announce`], which is the
/// only caller and the only place that knows which those are. Nothing else
/// may call it: releasing a flow whose identifier a caller already holds
/// would take away a live verification and report nothing.
fn forget_flow(flow_id: &str) {
    FLOWS
        .lock()
        .expect("verification registry poisoned")
        .remove(flow_id);
}

/// Records a comparison handle against a flow already in the registry.
///
/// Only ever called with the handle upstream just produced for that flow.
/// A miss means the registry released the flow between this call and the
/// one that fetched its handles, which another thread registering a flow in
/// that window can cause -- registering is what sweeps, and nothing holds a
/// lock across the two. Ignored rather than reported: there is no caller
/// mistake to report, the cache is an optimisation, and the next call
/// recovers the same handle from the request's own state.
fn remember_comparison(flow_id: &str, comparison: Sas) {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    if let Some(record) = flows.get_mut(flow_id) {
        record.comparison = Some(comparison);
    }
}

/// The handles for `flow`, from the registry or, failing that, from
/// upstream.
///
/// The second half is what lets this library answer a flow the *other* side
/// started. Nothing local ever registered it, so the identifier misses; it
/// is found by asking upstream about each user this machine tracks, which
/// is the set a verification counterparty is necessarily in (a device has
/// to have been queried before it can be verified).
///
/// # A request first, and a comparison only where there is no request
///
/// Upstream keeps requests and comparisons in two separate maps, and a
/// request-shaped flow whose comparison has started is in **both**. The
/// request is the handle that carries the comparison along with it and
/// that still knows the flow began as a request, so it is the one this
/// registers; the comparison map is reached only for a flow that is in no
/// other map, one that began as a bare `m.key.verification.start`.
///
/// **Nothing observable turns on that ordering today, and it is worth
/// saying so rather than implying otherwise.** A flow that has both
/// handles is always already in this registry: the peer cannot open a
/// comparison until this side has sent `m.key.verification.ready`, the
/// only call that sends one is [`accept_flow`], and that call registers
/// the flow before it sends anything. So this lookup never meets a flow
/// with both, and reversing the two arms changes no answer any call in
/// this module gives -- measured, not assumed. The ordering is here so
/// that a record is built from the handle that describes how the flow
/// began, which is the thing a later reader has no way to recover.
///
/// A flow found either way is registered only if it is still live. Adopting
/// a finished one would undo the eviction rule -- an identifier released by
/// `release_finished` would be picked straight back up from upstream's map
/// on the next mention of it, and the registry would grow by one entry per
/// verification the process ever ran.
async fn handles(flow: &FlowId) -> Result<Handles, MachineError> {
    if let Some(handles) = cached(&flow.0) {
        return Ok(handles);
    }

    let flow_id = flow.0.clone();
    let found = with_machine(move |machine| {
        Box::pin(async move {
            let tracked = machine
                .tracked_users()
                .await
                .map_err(|_upstream| store_failed())?;
            if let Some(request) = tracked
                .iter()
                .find_map(|user| machine.get_verification_request(user, &flow_id))
            {
                return Ok(Some(FlowRecord::from_request(request)));
            }
            Ok(tracked
                .iter()
                .find_map(|user| machine.get_verification(user, &flow_id))
                .and_then(Verification::sas_v1)
                .map(|comparison| FlowRecord::from_comparison(*comparison)))
        })
    })
    .await??;

    let mut record = found.ok_or(MachineError::UnknownFlow)?;
    if is_finished(stage_of(&mut record)) {
        return Err(MachineError::UnknownFlow);
    }
    let flow_id = upstream_flow_id(&record).ok_or(MachineError::UnknownFlow)?;

    Ok(register(&flow_id, record))
}

/// Hands one request upstream produced to the outbound pump.
///
/// Infallible by construction: upstream's own `From` impls carry both
/// shapes a verification can produce into the same request type the pump
/// already knows how to describe, id and all, so there is no conversion
/// here that could fail and no id for this module to mint.
fn queue(request: impl Into<UpstreamOutgoingRequest>) {
    crate::session::queue_action_request(request.into());
}

/// Asks a device to verify itself against this one.
///
/// Advertises exactly one method, the short authentication string, rather
/// than upstream's full default list: the other methods are not built here,
/// and advertising a method this library cannot carry out is a claim the
/// far side may act on.
pub async fn request_flow(user_id: &str, device_id: &str) -> Result<FlowId, MachineError> {
    // Owned before the closure, not borrowed, for the reason
    // `identity.rs` documents: `with_machine` requires a `'static` closure.
    let user_id = user_id.to_owned();
    let device_id = device_id.to_owned();

    let (flow_id, request, outgoing) = with_machine(move |machine| {
        Box::pin(async move {
            let user: OwnedUserId =
                user_id
                    .parse()
                    .map_err(|_| MachineError::MalformedIdentifier {
                        detail: "user id".to_string(),
                    })?;
            if device_id.is_empty() {
                return Err(MachineError::MalformedIdentifier {
                    detail: "device id".to_string(),
                });
            }
            let device: OwnedDeviceId = device_id.as_str().into();

            // `None`, not a timeout: waiting here would depend on the
            // caller draining the pump from another task while this call
            // holds the machine lock, which it cannot do. A caller that
            // does not know the device yet has to query for it and try
            // again -- reported as a named condition rather than as a wait
            // that quietly expires.
            let device = machine
                .get_device(&user, &device, None)
                .await
                .map_err(|_upstream| store_failed())?
                .ok_or(MachineError::UnknownDevice)?;

            let (request, outgoing) =
                device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
            Ok((request.flow_id().as_str().to_string(), request, outgoing))
        })
    })
    .await??;

    register(&flow_id, FlowRecord::from_request(request));
    queue(outgoing);

    Ok(FlowId(flow_id))
}

/// Asks this account's *other* devices to verify this one, so that this
/// device can join the signing identity the account already has.
///
/// # Why this is not [`request_flow`] with our own identifiers
///
/// Three differences, all of them upstream's and none of them cosmetic.
///
/// **It names no device.** [`request_flow`] asks one device, chosen by the
/// caller, through `Device::request_verification_with_methods`. This asks
/// through `OwnUserIdentity::request_verification_with_methods`, which fans
/// the invitation out to *every* other device of ours at once and lets
/// whichever is in front of a person answer first. A new login normally has
/// no idea which of its owner's devices is to hand, so choosing one is a
/// question it cannot answer; the ones that do not answer see the flow
/// cancelled when one does.
///
/// **The signature it ends in is made with a different key.** Upstream's
/// `mark_as_done` signs a device with our *self-signing* key when the device
/// is ours, and another user's master key with our *user-signing* key when
/// it is not (`verification/mod.rs:513`, `:549`). Both sides of a
/// self-verification take the first branch, and only the side that already
/// holds the private keys can act on it: the device with the identity signs
/// the new one, and the new one finds it has nothing to sign with and
/// carries on.
///
/// **It asks for the account's secrets, which verifying somebody else never
/// does.** Marking our own identity verified sets upstream's
/// `should_request_secrets`, which asks our other devices for whatever
/// cross-signing seeds this device lacks. Those become ordinary to-device
/// requests that [`crate::take_outgoing_requests`] hands out, and the reply
/// arrives encrypted inside a later [`crate::receive_sync_changes`], where
/// upstream imports it if and only if the sending device is one of ours and
/// is verified. **Nothing returns to the caller when that lands.**
/// [`crate::identity_status`]' `private_keys_held` is the durable answer,
/// and the `trust_changed` signal on [`crate::CryptoSignal`] is how a caller
/// learns of it without asking repeatedly.
///
/// # This is not a bootstrap, and must never become one
///
/// A device that does not hold the account's private signing keys **joins**
/// the identity the account already has. [`crate::bootstrap_identity`]
/// refuses such a device with [`MachineError::IdentityAlreadyExists`], and
/// that refusal is the one thing standing between an ordinary second login
/// and an account whose identity has been silently replaced, resetting the
/// trust of every device and every user who had verified the old one. This
/// call is the remedy that refusal points at; it is not a way around it.
///
/// # After it returns
///
/// The flow is driven exactly like [`request_flow`]'s: pump, wait for
/// [`FlowStage::Ready`], [`begin_comparison`], read the string with
/// [`read_material`], show it to a person, and [`confirm_flow`] or
/// [`cancel_flow`]. The person is comparing two of their own screens rather
/// than talking to somebody else, which changes nothing about the calls.
///
/// # Refusals
///
/// [`MachineError::AccountKeysNotFetched`] means this process has not asked
/// the server about this account yet, so it cannot know whether the account
/// has an identity to join. Same remedy as everywhere else this appears:
/// drain the pump, send, report sent, call again.
/// [`crate::bootstrap_identity`] queues that key query as it refuses, which
/// is the ordinary way a product reaches this point at all.
///
/// [`MachineError::IdentityNotKnown`] means the server was asked and named
/// no identity for this account. There is nothing to join, and the answer is
/// [`crate::bootstrap_identity`] rather than a retry.
pub async fn request_self_flow() -> Result<FlowId, MachineError> {
    let (flow_id, request, outgoing) = with_machine(|machine| {
        Box::pin(async move {
            // `None` as the timeout, not a duration, for the reason
            // `signing::read_status` gives at more length: with `Some`,
            // upstream waits for an in-flight key query for this account
            // while this call holds the machine lock, and the caller cannot
            // drain the pump to satisfy it from another task.
            let identity = machine
                .get_identity(machine.user_id(), None)
                .await
                .map_err(|_upstream| store_failed())?
                .and_then(|identity| identity.own());

            let Some(identity) = identity else {
                // The two refusals are separated by the same question
                // `signing::may_mint` asks first, read from the same place,
                // so this call and the bootstrap gate cannot come to
                // disagree about whether anybody has asked.
                return Err(if crate::session::account_keys_answered() {
                    MachineError::IdentityNotKnown
                } else {
                    MachineError::AccountKeysNotFetched
                });
            };

            // One method advertised, not upstream's default list, for
            // `request_flow`'s reason: advertising a method this library
            // cannot carry out is a claim the far side may act on.
            let (request, outgoing) = identity
                .request_verification_with_methods(vec![VerificationMethod::SasV1])
                .await
                .map_err(|_upstream| store_failed())?;
            Ok((request.flow_id().as_str().to_string(), request, outgoing))
        })
    })
    .await??;

    register(&flow_id, FlowRecord::from_request(request));
    queue(outgoing);

    Ok(FlowId(flow_id))
}

/// Agrees to whatever the other side is currently asking of this device.
///
/// # There are two things a peer can ask, and this call answers both
///
/// An `m.key.verification.request` asks *may we verify?*, and answering it
/// advertises the methods this library can carry out and moves the flow to
/// [`FlowStage::Ready`]. An `m.key.verification.start` asks *here is the
/// comparison, will you take part?*, and answering **that** is an
/// `m.key.verification.accept` naming the protocols both sides support --
/// the message the peer waits for before it will send its key.
///
/// Which of the two a flow needs depends on how it arrived and on who
/// moved first, and a caller does not have to work that out:
///
/// * a flow that arrived as a bare `m.key.verification.start` has no
///   request and skipped `Ready` entirely, so one call answers the
///   comparison;
/// * a flow that arrived as a request needs one call to answer the request
///   -- and **a second one if the peer then opens the comparison**, which
///   either side may do. Upstream builds the comparison and sends nothing
///   (`verification/requests.rs:1366-1396`), so until this is called again
///   the peer is waiting on a message no other call in this module
///   produces. Before that second call existed the flow simply stopped
///   there: `flow_stage` read `Started` forever, no error was returned
///   anywhere, and the string was never produced. That is the shape of
///   failure this whole module is written against.
///
/// So the rule is one sentence -- *call this whenever the flow is waiting
/// on your agreement* -- and [`flow_stage`] says when: `Requested` and
/// `Started` are both states where the answer is yours to give. The
/// difference between the two shapes is only that a bare-start flow is
/// never `Requested`, and that [`begin_comparison`] has nothing to do on
/// one.
///
/// # A refusal is never a silent no-op
///
/// Both handles report "not in a state where this applies" by returning
/// `None`: `VerificationRequest::accept_with_methods` for anything but
/// `Requested` (accepting our own request, or one already answered,
/// cancelled or finished), `Sas::accept` for anything but
/// `SasState::Started` (a comparison already accepted, cancelled or
/// finished). Neither is an absence, and neither is treated as one: they
/// are folded into [`MachineError::WrongStage`], which is what a caller
/// gets for a flow that is not waiting on it. [`flow_stage`] separates
/// "the other side is ahead" from "this is over" for free.
pub async fn accept_flow(flow: &FlowId) -> Result<(), MachineError> {
    let handles = handles(flow).await?;
    let outgoing = match (&handles.request, &handles.comparison) {
        // The request while there is a request to answer, and the
        // comparison once there is not. Not a precedence between two ways
        // of doing the same thing: at most one of the two is ever waiting
        // on an answer, so this is a search for whichever it is.
        (Some(request), comparison) => request
            .accept_with_methods(vec![VerificationMethod::SasV1])
            .or_else(|| comparison.as_ref().and_then(Sas::accept)),
        (None, Some(comparison)) => comparison.accept(),
        // Unreachable: `handles` returns a record built by one of
        // `FlowRecord`'s two constructors, each of which supplies a handle.
        // Mapped to the same error the two real arms produce rather than
        // left to a fallthrough that would report success.
        (None, None) => None,
    }
    .ok_or(MachineError::WrongStage)?;
    queue(outgoing);
    Ok(())
}

/// Starts the comparison itself, once both sides are ready.
///
/// Either side may call this, and only while the flow is at
/// [`FlowStage::Ready`]. Two sides calling it at the same moment is safe --
/// each has a ready flow when it calls, upstream settles which comparison
/// survives, and the loser's is dropped without disturbing the flow. What
/// is not safe, and is refused here, is the *same* side calling twice: by
/// the second call the flow is no longer ready, and the reason that has to
/// be an error rather than a second attempt is below.
///
/// **For whoever bridges this.** `WrongStage` here covers two conditions a
/// person needs told apart: "the other side started it, carry on and wait
/// for the string" and "this flow is over, start again". This is the one
/// place in this module those are folded, and folding them is deliberate --
/// both mean *this call* has nothing to do -- but a surface that shows a
/// user one sentence for both is showing the wrong one half the time.
/// [`flow_stage`] separates them for free: `Started` or later is the first,
/// `Cancelled` or `Done` is the second.
pub async fn begin_comparison(flow: &FlowId) -> Result<(), MachineError> {
    let handles = handles(flow).await?;

    // Rejected before upstream is asked, because upstream does not reject
    // it. `start_sas` on a flow that is already a comparison builds a
    // *second* one under the same identifier and hands it to a cache whose
    // documented behaviour is to cancel every duplicate it finds, "including
    // the newly inserted one" -- so both are cancelled, the flow is
    // destroyed, and this function would return `Ok(())` having queued the
    // opening message of a comparison that no longer exists. A double tap on
    // a button, or a retry after an unrelated failure, is enough. The doc
    // comment above is about two *sides* racing, which upstream does handle;
    // this is one side calling twice, which it does not. A side whose peer
    // got there first is refused for the same reason and with the same
    // error: there is nothing left for it to start, and the comparison it
    // wanted is already under way.
    let stage = stage_from(&handles);
    if stage != FlowStage::Ready {
        return Err(MachineError::WrongStage);
    }

    let flow_id = flow.0.clone();
    // Only a request-shaped flow can be `Ready`: that stage comes from
    // `VerificationRequestState::Ready` and nowhere else, and a flow that
    // arrived as a bare `m.key.verification.start` is a comparison from the
    // moment it exists -- it is refused by the check above, which is
    // correct, because the comparison this call would start is the one
    // already running.
    let request = handles.request.ok_or(MachineError::WrongStage)?;

    // Through `with_machine` like every other operation in this crate, and
    // not because the machine itself is needed: this call reaches the
    // crypto store, so it needs the runtime `with_machine` enters and the
    // serialisation against other store-touching work that holding the
    // machine lock gives it.
    let started = with_machine(move |_machine| Box::pin(async move { request.start_sas().await }))
        .await?
        .map_err(|_upstream| store_failed())?;

    let (comparison, outgoing) = started.ok_or(MachineError::WrongStage)?;
    remember_comparison(&flow_id, comparison);
    queue(outgoing);
    Ok(())
}

/// How far along the flow is.
pub async fn flow_stage(flow: &FlowId) -> Result<FlowStage, MachineError> {
    let handles = handles(flow).await?;
    Ok(stage_from(&handles))
}

/// The short authentication string, once there is one.
///
/// The two failure kinds are kept apart on purpose. `MaterialNotReady`
/// means the flow is live and has not got there yet, and it has two causes
/// that want opposite things done about them. `SasState::Accepted` is the
/// one this comment used to name alone: the key message was never reported
/// sent, which parks the flow at that stage forever, and the remedy is the
/// pump. `SasState::Started` is the other, and it is the receiving side's:
/// the peer opened the comparison and this side has not answered it, so the
/// remedy is a second [`accept_flow`] and pumping alone never moves it. The
/// facade reads [`flow_stage`] to tell a product which it is in.
/// `WrongStage` means it never will: the flow is over, or has not become a
/// comparison at all.
pub async fn read_material(flow: &FlowId) -> Result<SasMaterial, MachineError> {
    let handles = handles(flow).await?;
    let comparison = handles.comparison.ok_or(MachineError::WrongStage)?;

    match comparison.state() {
        SasState::KeysExchanged { emojis, decimals } => Ok(SasMaterial {
            emoji: emojis.map(|short_auth_string| {
                short_auth_string
                    .emojis
                    .iter()
                    .map(|emoji| SasEmoji {
                        symbol: emoji.symbol.to_string(),
                        description: emoji.description.to_string(),
                    })
                    .collect()
            }),
            decimals,
        }),
        SasState::Created { .. } | SasState::Started { .. } | SasState::Accepted { .. } => {
            Err(MachineError::MaterialNotReady)
        }
        SasState::Confirmed | SasState::Done { .. } | SasState::Cancelled(_) => {
            Err(MachineError::WrongStage)
        }
    }
}

/// Says the strings matched.
///
/// Only legal while the string is actually on screen. Upstream's own
/// `confirm` does nothing at all in any other state and reports success for
/// it, which would let a product confirm a verification it never showed
/// anybody; the stage is checked here first so that cannot happen quietly.
pub async fn confirm_flow(flow: &FlowId) -> Result<(), MachineError> {
    let handles = handles(flow).await?;
    let comparison = handles.comparison.ok_or(MachineError::WrongStage)?;

    match stage_of_comparison(&comparison) {
        FlowStage::KeysExchanged => {}
        FlowStage::Started => return Err(MachineError::MaterialNotReady),
        _ => return Err(MachineError::WrongStage),
    }

    let (requests, signature_upload) =
        with_machine(move |_machine| Box::pin(async move { comparison.confirm().await }))
            .await?
            .map_err(|_upstream| store_failed())?;

    for request in requests {
        queue(request);
    }
    // Produced only once this device has a cross-signing identity to sign
    // with. This said nothing in this library sets one up, and that
    // stopped being true when `signing::bootstrap_identity` landed, so the
    // precondition is now satisfiable and the branch is live rather than
    // dead.
    //
    // It is one of two producers of the same request, and which one fires
    // is decided by the flow's shape, not by anything here. Upstream
    // finishes a comparison from a confirmation only out of
    // `InnerSas::MacReceived` with `started_from_request` false, so a flow
    // that arrived as a bare start is signed *here*, while a flow that came
    // from a request is signed later, when the peer's own acknowledgement
    // arrives: `VerificationMachine::mark_sas_as_done` queues the request
    // for itself and it reaches the pump through
    // `OlmMachine::outgoing_requests()` like any other reaction. Both
    // therefore reach the pump, and neither needed a change here.
    //
    // **Only the second of the two is driven by a test.**
    // `tests/verified_sender.rs` verifies through a requested flow, and
    // that was confirmed rather than assumed: asserting `is_none()` here
    // leaves that test passing. So this branch's own firing is still
    // unwitnessed, and a test that drives a bare-start comparison against
    // a cross-signed counterparty is what would witness it.
    //
    // Queued rather than dropped, which is what mattered before either
    // could run: this is the message that publishes the verification to
    // the rest of the account, and without it the sender's master key
    // never carries our signature, so nothing this device verified would
    // ever read as an authenticated sender. See `SenderVerification`'s own
    // doc comment for what the signature is worth and what still has to
    // happen to it.
    if let Some(upload) = signature_upload {
        queue(upload);
    }

    // Nothing is announced from here, and on one flow shape that is now a
    // visible delay rather than a technicality.
    //
    // Upstream finishes a comparison from a confirmation only out of
    // `InnerSas::MacReceived`, and then only when `started_from_request` is
    // false (`verification/sas/inner_sas.rs:243-258`). A flow that came
    // from a request therefore always lands in `WaitingForDone` here --
    // which reads as `Confirmed` -- and its trust change arrives later
    // anyway, with the peer's own acknowledgement. **A flow that arrived as
    // a bare `m.key.verification.start` takes the other branch and is
    // `Done` when this call returns**, with the device already verified,
    // and yet still nothing is emitted: `announce_state_changes` runs from
    // `receive_sync_changes` and nowhere else, so its `TrustChanged` waits
    // for the next sync.
    //
    // Left that way on purpose. One producer, one moment, one ordering to
    // reason about -- a second producer here would have to take the
    // registry lock, mark the completion and race the sync path for it, to
    // save a delay a product does not experience, because it is syncing.
    // What a product must not do is read a returned `Ok` as a
    // verification; `flow_stage` and `device_statuses` are the answers to
    // that, and both are correct the instant this returns. The delay is
    // asserted in both directions -- silent before the next sync,
    // announced after it -- by
    // `a_comparison_started_without_a_request_is_announced_and_completes`.
    Ok(())
}

/// Refuses the verification, or abandons it.
///
/// The one call in this module a product must be able to make at any point
/// a person can look at a screen and say "that is not what I see". It
/// cancels the comparison if there is one -- which also cancels the request
/// behind it -- and the request otherwise.
pub async fn cancel_flow(flow: &FlowId) -> Result<(), MachineError> {
    let handles = handles(flow).await?;
    let outgoing = match (&handles.comparison, &handles.request) {
        (Some(comparison), _) => comparison.cancel(),
        (None, Some(request)) => request.cancel(),
        // Unreachable, for the reason `accept_flow` gives.
        (None, None) => None,
    }
    // Upstream returns `None` when the flow is already cancelled. Reported
    // rather than treated as success: "already refused" and "refused by
    // this call" are the same outcome, but a caller that gets `Ok` for a
    // flow it never actually cancelled has been told something false.
    .ok_or(MachineError::WrongStage)?;
    queue(outgoing);
    Ok(())
}

// ------------------------------------------------- the crypto signal channel

/// Every device a completed comparison verified, for flows whose completion
/// has not been announced yet, marking them announced on the way out.
///
/// Read from `SasState::Done`'s own `verified_devices` rather than from the
/// flow merely having finished. Upstream sets local trust only for the
/// devices that list names (`verification/mod.rs:710-719`), so a flow that
/// reached `Done` is not by itself a claim that anything became verified,
/// and a signal saying otherwise would be a false one.
///
/// Marks inside the same critical section that collects, so two callers
/// cannot both take the same completion. The cost is that a caller which
/// then fails to reach the machine loses the announcement -- acceptable,
/// because the only way to fail there is `NotInitialised`, and a process
/// with no machine has nothing to announce a trust change about.
///
/// Marks **every** `Done` record it inspects, not only the ones that
/// produced a completion. [`release_finished`] holds back a `Done` record
/// whose completion has not been taken, so a record this function looked at
/// and found nothing in must still come away marked, or it would be exempt
/// from eviction for the life of the process.
fn take_pending_completions() -> Vec<(OwnedUserId, OwnedDeviceId)> {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    let mut completions = Vec::new();

    for record in flows.values_mut() {
        if record.completion_announced {
            continue;
        }
        if stage_of(record) != FlowStage::Done {
            continue;
        }

        // Marked on the *stage*, before anything is read out of it, and
        // that is what `release_finished`'s exemption depends on: a record
        // it holds back must become sweepable on the next pass whether or
        // not it turned out to have anything to announce. A flow can reach
        // `Done` through `VerificationRequestState::Done` with no
        // comparison behind it at all, and marking only the ones that
        // produced a signal would exempt those from eviction for the life
        // of the process.
        record.completion_announced = true;

        // `state()` returns by value, which ends the borrow on `record`.
        let state = comparison_of(record).map(|comparison| comparison.state());
        let Some(SasState::Done {
            verified_devices, ..
        }) = state
        else {
            continue;
        };
        for device in verified_devices {
            completions.push((device.user_id().to_owned(), device.device_id().to_owned()));
        }
    }

    completions
}

/// The `(sender, transaction id)` of every `m.key.verification.start` among
/// one sync's processed to-device events.
///
/// Read from what upstream handed *back*, never from what the caller passed
/// in, and the difference is not cosmetic: a verification event may arrive
/// Olm-encrypted, in which case `receive_sync_changes` returns the
/// decrypted event in its place (`ProcessedToDeviceEvent::Decrypted`).
/// Parsing the input would see `m.room.encrypted` and miss every encrypted
/// flow, silently.
///
/// A candidate is no more than a transaction id that might name a flow.
/// Nothing is announced from one until upstream has confirmed it; see
/// [`announce_state_changes`], which is the only caller.
fn bare_start_candidates(processed: &[ProcessedToDeviceEvent]) -> Vec<(OwnedUserId, String)> {
    processed
        .iter()
        .filter_map(|event| {
            let raw = event.as_raw().json().get();
            // A substring test before the parse. This runs once per
            // to-device event on a path that also carries every room key a
            // product receives, and a full parse of each would be real
            // per-sync work for a message type that appears only while
            // somebody is verifying.
            if !raw.contains(START_EVENT_TYPE) {
                return None;
            }
            let event: serde_json::Value = serde_json::from_str(raw).ok()?;
            if event.get("type")?.as_str()? != START_EVENT_TYPE {
                return None;
            }
            let sender: OwnedUserId = event.get("sender")?.as_str()?.parse().ok()?;
            let transaction = event.get("content")?.get("transaction_id")?.as_str()?;
            Some((sender, transaction.to_string()))
        })
        .collect()
}

/// The to-device event that opens a comparison.
///
/// Matched as a candidate only; nothing is believed on its say-so. See
/// [`bare_start_candidates`].
const START_EVENT_TYPE: &str = "m.key.verification.start";

/// Emits everything the crypto signal channel owes its subscribers, and
/// returns having emitted nothing when there are none.
///
/// Called from [`crate::receive_sync_changes`], and from nowhere else,
/// because that is the only moment either kind of change can happen: an
/// invitation exists once the event that carries it has been fed in, and a
/// comparison reaches `Done` only when the peer's acknowledgement arrives
/// (see [`confirm_flow`] for why confirming cannot finish one here).
///
/// # It asks what has changed rather than being told
///
/// Nothing on this path is driven by a particular event. It compares the
/// registry against what has already been announced, which is what makes it
/// correct under interleavings nobody enumerated: two transitions in one
/// sync are both announced, a transition that happens for a reason this
/// file did not predict is still announced, and calling it twice announces
/// nothing twice.
///
/// # Nothing is emitted from under the machine lock
///
/// The whole collection runs inside one `with_machine` closure and every
/// signal is emitted after it returns. `observer::emit_crypto` detaches
/// delivery anyway, so this is not what makes it safe -- but a listener
/// must never observe a signal before the operation that produced it has
/// visibly completed, and that is what the ordering here buys.
///
/// # What it costs
///
/// **With nobody listening, nothing.** The observer is read first, and with
/// none registered this returns before it takes the registry lock or
/// reaches the crypto store. That matters because the sync path calls this
/// on every sync a product performs, which is the highest-frequency call
/// this library has -- and it is why the TypeScript side uninstalls the
/// observer on the last unsubscribe rather than leaving it latched.
///
/// **With somebody listening, one `tracked_users()` and one
/// `get_verification_requests` per tracked user, per sync.** Measured
/// against an empty sync on an account with one tracked user, the
/// difference was below the resolution of the measurement -- but
/// `tracked_users` clones the whole tracked-user set into a fresh
/// `HashSet<OwnedUserId>` (`machine/mod.rs:482`), so on an account tracking
/// thousands that is an allocation proportional to the account on this
/// library's most frequent call. Nothing here has measured that case, and
/// the small-account figure must not be read as covering it.
///
/// # A verification begun without a request
///
/// A peer that starts a comparison the deprecated way -- an
/// `m.key.verification.start` with no `m.key.verification.request` before
/// it -- takes upstream's other branch
/// (`verification/machine.rs:430-450`): `Sas::from_start_event` followed by
/// `verifications.insert_sas`, which writes to the comparison cache and
/// *nothing* to the `requests` map the enumeration below reads. Such a flow
/// cannot be enumerated at all -- `VerificationCache` offers keyed lookup
/// and no listing -- so it is announced from `processed` instead.
///
/// Announced *from* it, not *off* it. The transaction id read off the start
/// event is only a candidate; the flow is then confirmed against upstream
/// through `OlmMachine::get_verification` (`machine/mod.rs:1444`), and
/// everything the announcement carries is read back off the comparison
/// upstream produced rather than off the wire. That keeps this function's
/// one invariant: never hand a product an identifier that no call in this
/// module answers to. A start from a device this machine has never met
/// builds no comparison -- upstream's branch returns without one when
/// `get_device` misses -- so nothing is announced for it, which is the same
/// rule, with the same remedy, as the request-shaped invitation from an
/// unmet device.
///
/// # The one property the two shapes do not share
///
/// A request-shaped invitation that arrives while nobody is subscribed is
/// announced on the first sync after somebody subscribes, because it is
/// re-enumerated from upstream every time -- and, since [`announce`]
/// releases what it could not deliver, that holds for an unsubscribe
/// landing *inside* this function too, not only for one that beat it here.
/// **A bare start is not.** Its
/// only witness is the sync that carried it, and this function returns
/// before looking at `processed` when there is no observer. Nothing cheaper
/// closes that: upstream has no enumerator to ask later, and the event is
/// delivered once. A product that wants inbound invitations has to
/// subscribe before it starts syncing, which is what the facade already
/// tells it to do -- and which is now load-bearing for one flow shape
/// rather than merely advisable for both.
pub(crate) async fn announce_state_changes(processed: &[ProcessedToDeviceEvent]) {
    // Silent by default, and free by default. See the doc comment above.
    if crate::observer::crypto_observer().is_none() {
        return;
    }

    let completions = take_pending_completions();
    let candidates = bare_start_candidates(processed);

    let collected = with_machine(move |machine| {
        Box::pin(async move {
            let mut signals: Vec<CryptoSignal> = Vec::new();

            // Read the devices back rather than trusting that the
            // comparison naming them made them verified. `device_statuses`
            // asks upstream exactly this question, and asking it the same
            // way here is what stops the channel and the call from ever
            // disagreeing about a device.
            let mut changed: BTreeSet<String> = BTreeSet::new();
            for (user, device) in completions {
                let verified = machine
                    .get_device(&user, &device, None)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|device| device.is_verified());
                if verified {
                    changed.insert(user.to_string());
                }
            }
            for user in changed {
                signals.push(CryptoSignal::TrustChanged {
                    user,
                    state: TrustState::Verified,
                });
            }

            // The account's own private signing keys arriving, which is a
            // trust change no comparison of this device's own reports.
            //
            // A device that joins an identity by verifying itself against
            // another of ours asks that device for the seeds it lacks, and
            // the answer comes back inside a later `receive_sync_changes` as
            // an encrypted secret upstream imports on its own. Nothing
            // returns to the caller when it lands, and nothing else on this
            // surface changes, so without this a product would have to poll
            // `identity_status` to find out that its new device can sign.
            //
            // The latch is what makes this an arrival rather than a report
            // repeated on every sync; `signing::note_private_keys_held`
            // owns it. Announced under our own user id, which is the shape
            // this variant has carried since M1: which of that user's
            // devices moved is `device_statuses`' answer, and here the
            // answer is potentially all of them at once, because a device
            // that holds the self-signing key can follow the account's own
            // signature over every device it signed.
            //
            // Consumed if it reaches nobody, like the completions above and
            // unlike an inbound invitation. `identity_status().private_keys_held`
            // is the durable answer and is correct the instant the import
            // lands, so a missed announcement costs a caller one call rather
            // than a state it can never recover.
            if crate::signing::note_private_keys_held(
                machine.cross_signing_status().await.is_complete(),
            ) {
                signals.push(CryptoSignal::TrustChanged {
                    user: machine.user_id().to_string(),
                    state: TrustState::Verified,
                });
            }

            // Inbound invitations. Enumerated from upstream rather than by
            // parsing the to-device events a sync carried, and the
            // difference is the point of the variant: upstream builds a
            // flow only when it can, so an invitation from a device this
            // machine has never met produces no flow and is therefore not
            // announced. Announcing on the wire event instead would hand a
            // product an identifier that no call of this library answers
            // to. The same rule is what makes a *re-fed* invitation
            // announce itself: the second arrival is when the flow first
            // exists.
            //
            // `tracked_users` is the same set `handles` searches, for the
            // same reason: a device has to have been queried before it can
            // be verified, so a counterparty is necessarily in it.
            let tracked = machine.tracked_users().await.unwrap_or_default();
            for user in &tracked {
                for request in machine.get_verification_requests(user) {
                    // `Requested` and nothing else: `Created` is a flow this
                    // device asked for and whose identifier the caller
                    // already holds, and a request another of our own
                    // devices answered presents as `Cancelled`.
                    let VerificationRequestState::Requested {
                        other_device_data, ..
                    } = request.state()
                    else {
                        continue;
                    };
                    let flow_id = request.flow_id().as_str().to_string();
                    let announcement = CryptoSignal::VerificationRequested {
                        user: request.other_user().to_string(),
                        device_id: other_device_data.device_id().to_string(),
                        flow_id: flow_id.clone(),
                    };
                    // Registering is the deduplication: a flow this
                    // registry already holds has been announced, or was
                    // started here and needs no announcement.
                    if register_if_absent(&flow_id, FlowRecord::from_request(request)) {
                        signals.push(announcement);
                    }
                }
            }

            // Inbound comparisons nobody requested: the deprecated shape,
            // reached from this sync's own start events because upstream
            // keeps them where nothing can enumerate them. See this
            // function's header.
            for (sender, transaction) in candidates {
                // A request wins wherever there is one, which is
                // `handles`'s rule, kept local here rather than argued
                // from a distance. A request-shaped flow whose comparison
                // has started carries an `m.key.verification.start` too,
                // and a record built from that start alone would hold no
                // request handle.
                //
                // Stated plainly: nothing reaches this line today. Such a
                // flow is already in the registry by the time its start
                // arrives -- the peer cannot start one until this side has
                // sent `m.key.verification.ready`, and the only call that
                // sends one registers the flow first -- so
                // `register_if_absent` below would refuse it anyway. That
                // is an argument about four other functions, and this is
                // one map lookup.
                if machine
                    .get_verification_request(&sender, &transaction)
                    .is_some()
                {
                    continue;
                }
                let Some(comparison) = machine
                    .get_verification(&sender, &transaction)
                    .and_then(Verification::sas_v1)
                else {
                    continue;
                };
                let comparison = *comparison;

                let mut record = FlowRecord::from_comparison(comparison.clone());
                // A flow already over announces nothing. Registering one
                // would also undo the eviction rule, for the reason
                // `handles` gives about adopting a finished flow.
                if is_finished(stage_of(&mut record)) {
                    continue;
                }

                let flow_id = comparison.flow_id().as_str().to_string();
                let announcement = CryptoSignal::VerificationRequested {
                    user: comparison.other_user_id().to_string(),
                    device_id: comparison.other_device_id().to_string(),
                    flow_id: flow_id.clone(),
                };
                // The same deduplication the request path uses, and it is
                // also what keeps a flow this process started from being
                // announced back to it: its identifier is already here.
                if register_if_absent(&flow_id, record) {
                    signals.push(announcement);
                }
            }

            signals
        })
    })
    .await;

    // A machine that has gone away has nothing to announce. Swallowed
    // rather than reported: this is a notification path with no caller to
    // return an error to, and it must never turn a successful sync into a
    // failed one.
    let Ok(signals) = collected else {
        return;
    };

    announce(signals);
}

/// Hands this pass's signals to the channel, and puts back what announcing
/// an invitation to nobody consumed.
///
/// # The window this exists for
///
/// [`announce_state_changes`] reads the observer registry **once**, at
/// entry, and everything after that reads is consumption:
/// [`register_if_absent`] inserts the inbound flow, and that insertion *is*
/// the deduplication which stops the same invitation being announced twice.
/// Delivery happens here, last. An unsubscribe arriving in between --
/// which the ordinary `useEffect(() => onCryptoSignal(h), [])` produces,
/// because the JavaScript thread is free while `await
/// receiveSyncChanges(..)` is in flight -- therefore used to leave the
/// invitation registered and undelivered: refused by `register_if_absent`
/// for the rest of its life, listed by no call, expiring silently ten
/// minutes later. That is exactly the consequence
/// [`crate::observer::clear_crypto_observer`] was written to prevent, and
/// it survived inside it through a narrower window: one sync call rather
/// than the whole time a product is unsubscribed.
///
/// So a signal that reaches nobody releases the registration that producing
/// it made, and the flow is enumerated and announced afresh by the next
/// pass that has somebody to announce it to.
///
/// # Why the flow identifier can be read off the signal
///
/// `forget_flow` is destructive and must never touch a flow a caller
/// already holds. It cannot here: [`announce_state_changes`] pushes a
/// `VerificationRequested` only where `register_if_absent` returned
/// `true`, and a flow this process started, or was already told about, is
/// in the registry and makes it return `false`. So every
/// `VerificationRequested` this function sees names a flow the same pass
/// inserted, and nothing else does. That is the contract: **only ever
/// called with the signals one announcement pass just produced.**
///
/// # What is deliberately not put back
///
/// A `TrustChanged` whose delivery finds nobody stays consumed --
/// [`take_pending_completions`] has already marked the record, and
/// un-marking it would re-exempt the record from eviction. It is not the
/// same loss: which devices are verified is `device_statuses`' durable
/// answer and always was, so a missed trust change is re-askable and a
/// missed invitation is not. `signals.ts` says the same thing to a product
/// in the same words.
///
/// # What it still does not close
///
/// [`crate::observer::emit_crypto`] reports whether an observer was
/// registered when it read the registry, not whether the listener behind it
/// still existed when the detached delivery thread ran. An unsubscribe
/// landing in *that* gap is indistinguishable from a delivery here, and
/// closing it would mean holding the observer registry's lock across a
/// foreign call from inside the sync path. `clear_crypto_observer` records
/// that residue with its measured bound.
fn announce(signals: Vec<CryptoSignal>) {
    for signal in signals {
        // Read before the move, not after: `emit_crypto` takes the signal
        // by value, and the identifier is needed only on the arm where it
        // did not go anywhere.
        let registered = match &signal {
            CryptoSignal::VerificationRequested { flow_id, .. } => Some(flow_id.clone()),
            // The only other variant, and the one whose consumption is
            // recoverable; see this function's header. Matched by name
            // rather than by `_` so a variant added later has to be ruled
            // on here instead of silently joining it.
            CryptoSignal::TrustChanged { .. } => None,
        };
        if crate::observer::emit_crypto(signal) {
            continue;
        }
        if let Some(flow_id) = registered {
            forget_flow(&flow_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every public error this module can produce is a `MachineError`
    /// variant appended after the five the enum shipped with, and the FFI
    /// mirror's `From` impl is exhaustive, so this only has to pin the
    /// mapping this module relies on: three distinct conditions, three
    /// distinct errors, none of them collapsed into another.
    #[test]
    fn the_three_flow_errors_are_distinct() {
        assert_ne!(MachineError::UnknownFlow, MachineError::WrongStage);
        assert_ne!(MachineError::WrongStage, MachineError::MaterialNotReady);
        assert_ne!(MachineError::UnknownFlow, MachineError::MaterialNotReady);
    }

    /// The redacting `Debug` impls, checked against the strings they must
    /// never contain. `MachineConfig` and `Envelope` have the same test for
    /// the same reason: a derived `Debug` reintroduced later would pass
    /// every other test in this crate.
    #[test]
    fn the_authentication_material_never_reaches_a_debug_line() {
        let material = SasMaterial {
            emoji: Some(vec![SasEmoji {
                symbol: "\u{1f436}".to_string(),
                description: "Dog".to_string(),
            }]),
            decimals: (1234, 5678, 9012),
        };
        let rendered = format!("{material:?}");
        assert!(
            !rendered.contains("1234") && !rendered.contains("5678") && !rendered.contains("9012"),
            "the decimal short authentication string must not be printable: {rendered}"
        );
        assert!(
            !rendered.contains('\u{1f436}') && !rendered.contains("Dog"),
            "the symbol short authentication string must not be printable: {rendered}"
        );
        let one = format!(
            "{:?}",
            SasEmoji {
                symbol: "\u{1f436}".to_string(),
                description: "Dog".to_string(),
            }
        );
        assert!(
            !one.contains('\u{1f436}') && !one.contains("Dog"),
            "one symbol is a seventh of the answer and must not be printable: {one}"
        );
    }

    const OTHER_USER: &str = "@other:example.org";
    const OTHER_DEVICE: &str = "OTHERDEVICE";

    /// Teaches the live machine about one device of another user, so a flow
    /// can be started against it.
    ///
    /// Built the same way `session.rs`'s own tests build one: a bare
    /// upstream machine publishes real, self-signed device keys, and those
    /// keys come back through this crate's own pump as the response to a
    /// device query. Fabricated keys would be rejected, and no shortcut
    /// through `with_machine` is needed because the shipped surface can
    /// already do all of it.
    async fn teach_the_machine_about_a_device() {
        let other_user: matrix_sdk_common::ruma::OwnedUserId = OTHER_USER.parse().unwrap();
        let other_device: matrix_sdk_common::ruma::OwnedDeviceId = OTHER_DEVICE.into();
        let other = matrix_sdk_crypto::OlmMachine::new(&other_user, &other_device).await;
        let device_keys = other
            .outgoing_requests()
            .await
            .unwrap()
            .iter()
            .find_map(|request| match request.request() {
                matrix_sdk_crypto::types::requests::AnyOutgoingRequest::KeysUpload(upload) => {
                    upload.device_keys.clone()
                }
                _ => None,
            })
            .expect("a fresh machine always has device keys to upload");

        crate::session::receive_sync_changes(&format!(
            r#"{{"changed_devices":{{"changed":["{OTHER_USER}"],"left":[]}}}}"#
        ))
        .await
        .unwrap();
        let query_id = crate::session::take_outgoing_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.kind == "keys_query")
            .expect("a machine that has been told a user changed asks about them")
            .id;
        crate::session::mark_request_sent(
            &query_id,
            &serde_json::json!({
                "device_keys": {
                    OTHER_USER: { OTHER_DEVICE: serde_json::to_value(&device_keys).unwrap() }
                }
            })
            .to_string(),
        )
        .await
        .unwrap();
    }

    /// The registry must be emptied while the machine still holds the store,
    /// not after it has been dropped.
    ///
    /// This test exists because getting that backwards does not fail an
    /// assertion. A registry entry holds an upstream verification handle,
    /// which holds an `Arc` on the crypto store; if `reset_for_test` drops
    /// the machine first, the entry's reference becomes the last one and is
    /// released on this bare synchronous test thread, where closing the
    /// pooled Sqlite connections panics with "no reactor running" -- twice,
    /// in a destructor, which is a non-unwinding panic that **aborts the
    /// whole test process** with SIGABRT. So the failure this guards
    /// against does not appear as a red test; it appears as the suite
    /// dying, which is why it needs a test that actually registers a flow
    /// rather than a comment saying it would matter if one ever did.
    /// Deliberately **not** `#[tokio::test]`, unlike its neighbours. The
    /// hazard exists only on a thread with no runtime in scope, and an
    /// ambient one hides it completely: under `#[tokio::test]` this passes
    /// whichever order the two statements are in, which was measured rather
    /// than assumed. So the setup runs inside `in_runtime` and the call
    /// under test runs outside it, on the bare synchronous thread
    /// `block_on` is driving -- which is where a test process actually is
    /// when it calls this.
    #[test]
    fn the_registry_is_emptied_before_the_store_it_holds_alive_is_dropped() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        // Held for the whole test rather than moved into the block below:
        // the store directory must not be deleted out from under the
        // machine that is still using it.
        let dir = tempfile::tempdir().unwrap();
        let machine_config = config(dir.path());

        let registered = futures::executor::block_on(crate::in_runtime(async move {
            crate::machine::create_machine(machine_config)
                .await
                .unwrap();
            teach_the_machine_about_a_device().await;
            let flow = request_flow(OTHER_USER, OTHER_DEVICE)
                .await
                .expect("a device the machine has been told about can be asked to verify");
            assert_eq!(
                flow_stage(&flow).await.expect("the flow exists"),
                FlowStage::Requested
            );
            flow_count()
        }));
        assert_eq!(
            registered, 1,
            "this test proves nothing unless the registry is actually holding a handle"
        );

        // The call under test, from a thread with no runtime in scope. It
        // either releases the registry's handle while the machine still
        // holds the store -- in which case this returns and the assertion
        // below runs -- or it makes the registry's the last reference and
        // drops the store here, in which case there is no assertion to
        // reach because the process is gone.
        crate::machine::reset_for_test();
        assert_eq!(
            flow_count(),
            0,
            "the registry must be empty once the machine it belongs to is gone"
        );
    }

    fn config(dir: &std::path::Path) -> crate::machine::MachineConfig {
        crate::machine::MachineConfig {
            user_id: "@self:example.org".to_string(),
            device_id: "SELFDEVICE".to_string(),
            store_path: dir.join("store").to_string_lossy().into_owned(),
            store_passphrase: Some("test-passphrase".to_string()),
        }
    }

    /// A device this machine has never been told about is not the same
    /// condition as an identifier that does not parse, and the two must not
    /// arrive as one error.
    ///
    /// They were one error until a review pointed out that they call for
    /// different things: the first is fixed by querying that user's devices
    /// through the pump and trying again, the second by passing something
    /// else. Both assertions are here because the pair is the point; either
    /// one alone would keep passing if the fold came back.
    #[tokio::test]
    async fn an_unknown_device_is_not_reported_as_a_malformed_identifier() {
        let _guard = crate::machine::lock_for_test().await;
        crate::machine::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        crate::machine::create_machine(config(dir.path()))
            .await
            .unwrap();

        assert_eq!(
            request_flow("@nobody:example.org", "NOSUCHDEVICE")
                .await
                .expect_err("this machine has never queried that user"),
            MachineError::UnknownDevice
        );
        assert_eq!(
            request_flow("not-a-user-id", "NOSUCHDEVICE")
                .await
                .expect_err("that identifier does not parse"),
            MachineError::MalformedIdentifier {
                detail: "user id".to_string()
            }
        );

        crate::machine::reset_for_test();
    }

    /// A listener that does nothing, so a test can put an observer in the
    /// registry without also building a channel to read.
    struct Silent;

    impl crate::observer::CryptoObserver for Silent {
        fn on_signal(&self, _signal: CryptoSignal) {}
    }

    /// An announcement that reaches nobody must put back the registration
    /// that producing it made.
    ///
    /// # What it is protecting
    ///
    /// [`announce_state_changes`] reads the observer registry once, at
    /// entry, and consumes afterwards: `register_if_absent` inserts the
    /// inbound flow, and that insertion is the deduplication. So an
    /// unsubscribe landing between the entry read and the delivery left the
    /// invitation registered and undelivered -- announced to nobody, then
    /// refused to everybody, and gone when it expired ten minutes later.
    /// The same consequence `clear_crypto_observer` exists to prevent,
    /// surviving inside it through a one-sync window.
    ///
    /// # Why this is a unit test and not a race
    ///
    /// The window was reproduced through the public surface before it was
    /// closed, by racing `clear_crypto_observer` against
    /// `receive_sync_changes` on the `tests/sas_two_party.rs` arrangement,
    /// sweeping the unsubscribe across the sync in five-microsecond steps:
    /// an unsubscribe 76us before a 5.0ms sync returned consumed the
    /// invitation, and the next subscriber was never told about it. That
    /// reproduction is not kept, because it cannot be kept honestly. The
    /// announcing pass is the last few tens of microseconds of that five
    /// milliseconds, so a timing sweep lands in it on this machine and need
    /// not on another -- and once the loss is fixed, an unsubscribe before
    /// the entry guard and one after it are indistinguishable from outside,
    /// so nothing in such a test could assert that it had reached the state
    /// it is about. A check that reports success without examining its
    /// target is the failure this repository keeps finding; this one drives
    /// the seam instead, where the interleaving is decided rather than
    /// hoped for.
    ///
    /// The flow here is one this process started, which
    /// [`announce_state_changes`] would never announce -- it is in the
    /// registry, so `register_if_absent` returns `false` for it. That is
    /// the point: it stands in for "a flow the registry holds", and what is
    /// under test is what [`announce`] does with the pairing its caller
    /// hands it, which is the half a race cannot pin down.
    #[tokio::test]
    async fn an_invitation_announced_to_nobody_is_released_rather_than_left_registered() {
        let _guard = crate::machine::lock_for_test().await;
        crate::machine::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        crate::machine::create_machine(config(dir.path()))
            .await
            .unwrap();
        teach_the_machine_about_a_device().await;

        let flow = request_flow(OTHER_USER, OTHER_DEVICE)
            .await
            .expect("a device the machine has been told about can be asked to verify");
        assert_eq!(
            flow_count(),
            1,
            "this test proves nothing unless the registry is actually holding the flow"
        );
        let invitation = || CryptoSignal::VerificationRequested {
            user: OTHER_USER.to_string(),
            device_id: OTHER_DEVICE.to_string(),
            flow_id: flow.0.clone(),
        };

        // Somebody is listening: the signal is taken, and the registration
        // that produced it stands. Asserted first, because a `forget_flow`
        // that fired unconditionally would pass every assertion below.
        crate::observer::set_crypto_observer(std::sync::Arc::new(Silent));
        announce(vec![invitation()]);
        assert_eq!(
            flow_count(),
            1,
            "an invitation that reached a subscriber must stay registered, or the next sync \
             announces it a second time"
        );

        // Nobody is listening, and the consumption is not the same in both
        // directions. A trust change is re-askable through `device_statuses`
        // and its record must not be released with it -- `release_finished`
        // is what evicts a finished flow, on its own rule.
        crate::observer::clear_crypto_observer();
        announce(vec![CryptoSignal::TrustChanged {
            user: OTHER_USER.to_string(),
            state: TrustState::Verified,
        }]);
        assert_eq!(
            flow_count(),
            1,
            "a trust change nobody heard must not take a live flow with it"
        );

        // The invitation is the one that cannot be re-asked for, so it is
        // the one that has to be put back.
        announce(vec![invitation()]);
        assert_eq!(
            flow_count(),
            0,
            "an invitation announced to nobody must release its registration: leaving it is \
             what makes `register_if_absent` refuse the flow for the rest of its life, with no \
             call that lists inbound flows to recover it from"
        );

        crate::machine::reset_for_test();
    }

    /// A flow nothing ever registered, on a process with no machine at all:
    /// the registry misses, the resolution against upstream cannot even be
    /// attempted, and the caller is told so rather than left waiting.
    #[tokio::test]
    async fn an_identifier_no_flow_ever_had_is_reported() {
        let _guard = crate::machine::lock_for_test().await;
        crate::machine::reset_for_test();

        let error = flow_stage(&FlowId("not-a-flow".to_string()))
            .await
            .expect_err("no machine exists, so no flow can be found");
        assert_eq!(error, MachineError::NotInitialised);
    }
}
