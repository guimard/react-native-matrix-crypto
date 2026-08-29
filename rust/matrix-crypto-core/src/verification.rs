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

use matrix_sdk_common::ruma::events::key::verification::VerificationMethod;
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId};
use matrix_sdk_crypto::types::requests::OutgoingRequest as UpstreamOutgoingRequest;
use matrix_sdk_crypto::{Sas, SasState, VerificationRequest, VerificationRequestState};

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
    request: VerificationRequest,
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
    request: VerificationRequest,
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
        if let VerificationRequestState::Transitioned { verification, .. } = record.request.state()
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
    // Exhaustive, no wildcard, like every other upstream match in this
    // crate: a state upstream adds later must fail this build rather than
    // be reported as whichever stage a wildcard happened to name.
    match record.request.state() {
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

/// Drops every flow that has finished.
///
/// Upstream's own rule, `retain(|_, v| !(v.is_done() || v.is_cancelled()))`
/// from `VerificationMachine::garbage_collect`, run here at the one moment
/// this registry can grow rather than on every sync. See the module's own
/// header for what that costs a caller and why it is bounded.
fn release_finished(flows: &mut BTreeMap<String, FlowRecord>) {
    flows.retain(|_, record| !is_finished(stage_of(record)));
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

fn register(flow_id: &str, request: VerificationRequest) -> Handles {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    release_finished(&mut flows);
    let record = flows.entry(flow_id.to_string()).or_insert(FlowRecord {
        request,
        comparison: None,
        completion_announced: false,
    });
    let comparison = comparison_of(record).cloned();
    Handles {
        request: record.request.clone(),
        comparison,
    }
}

/// Registers `request` under `flow_id` if the registry does not already
/// hold that flow, and reports whether it did.
///
/// Separate from [`register`] because the announcement path needs the
/// insertion and the "was it new?" question answered under one lock. Split
/// into a `contains_key` and a `register`, an inbound flow could be
/// announced twice by two syncs that interleaved between them.
fn register_if_absent(flow_id: &str, request: VerificationRequest) -> bool {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    if flows.contains_key(flow_id) {
        return false;
    }
    release_finished(&mut flows);
    flows.insert(
        flow_id.to_string(),
        FlowRecord {
            request,
            comparison: None,
            completion_announced: false,
        },
    );
    true
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
/// A flow found that way is registered only if it is still live. Adopting a
/// finished one would undo the eviction rule -- an identifier released by
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
            Ok(tracked
                .iter()
                .find_map(|user| machine.get_verification_request(user, &flow_id)))
        })
    })
    .await??;

    let request = found.ok_or(MachineError::UnknownFlow)?;
    let flow_id = request.flow_id().as_str().to_string();
    let mut probe = FlowRecord {
        request: request.clone(),
        comparison: None,
        completion_announced: false,
    };
    if is_finished(stage_of(&mut probe)) {
        return Err(MachineError::UnknownFlow);
    }

    Ok(register(&flow_id, request))
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

    register(&flow_id, request);
    queue(outgoing);

    Ok(FlowId(flow_id))
}

/// Agrees to a verification the other side asked for.
pub async fn accept_flow(flow: &FlowId) -> Result<(), MachineError> {
    let handles = handles(flow).await?;
    // `None` from upstream means "not in a state where this applies" --
    // accepting our own request, or one already answered, cancelled or
    // finished. Reported, never treated as a successful no-op.
    let outgoing = handles
        .request
        .accept_with_methods(vec![VerificationMethod::SasV1])
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
    let request = handles.request;

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
/// means the flow is live and has not got there yet -- and, far more often
/// in practice, that the key message was never reported sent, which parks
/// the flow at exactly this stage forever. `WrongStage` means it never
/// will: the flow is over, or has not become a comparison at all.
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
    // with, which nothing in this library sets up yet, so this is a branch
    // that does not run today. Queued rather than dropped anyway: it is the
    // message that would publish the verification to the rest of the
    // account, and a silently discarded one would be invisible on every
    // other device.
    if let Some(upload) = signature_upload {
        queue(upload);
    }

    // Nothing is announced from here, and the reason is upstream's rather
    // than a decision taken in this file. A confirmation can only finish a
    // comparison outright from `InnerSas::MacReceived`, and only when
    // `started_from_request` is false
    // (`verification/sas/inner_sas.rs:243-258`); every flow this library
    // runs comes from a request, so this call always leaves the comparison
    // in `WaitingForDone` -- which reads as `Confirmed`, not `Done`. The
    // trust change therefore always arrives with the peer's own
    // acknowledgement, through `receive_sync_changes`, and putting a
    // producer here as well would add a branch nothing can reach.
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
    let outgoing = match &handles.comparison {
        Some(comparison) => comparison.cancel(),
        None => handles.request.cancel(),
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
fn take_pending_completions() -> Vec<(OwnedUserId, OwnedDeviceId)> {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    let mut completions = Vec::new();

    for record in flows.values_mut() {
        if record.completion_announced {
            continue;
        }
        // `state()` returns by value, which ends the borrow on `record`
        // before its `completion_announced` is written below.
        let state = comparison_of(record).map(|comparison| comparison.state());
        let Some(SasState::Done {
            verified_devices, ..
        }) = state
        else {
            continue;
        };
        record.completion_announced = true;
        for device in verified_devices {
            completions.push((device.user_id().to_owned(), device.device_id().to_owned()));
        }
    }

    completions
}

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
/// # What it costs when nobody is listening
///
/// Nothing. The observer is read first, and with none registered this
/// returns before it takes the registry lock or reaches the crypto store.
/// That matters because the sync path calls this on every sync a product
/// performs, which is the highest-frequency call this library has.
pub(crate) async fn announce_state_changes() {
    // Silent by default, and free by default. See the doc comment above.
    if crate::observer::crypto_observer().is_none() {
        return;
    }

    let completions = take_pending_completions();

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
                    if register_if_absent(&flow_id, request) {
                        signals.push(announcement);
                    }
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

    for signal in signals {
        crate::observer::emit_crypto(signal);
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
