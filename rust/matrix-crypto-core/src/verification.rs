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

use std::collections::BTreeMap;
use std::sync::Mutex as StdMutex;

use matrix_sdk_common::ruma::events::key::verification::VerificationMethod;
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId};
use matrix_sdk_crypto::types::requests::OutgoingRequest as UpstreamOutgoingRequest;
use matrix_sdk_crypto::{Sas, SasState, VerificationRequest, VerificationRequestState};

use crate::machine::{with_machine, MachineError};

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
    });
    let comparison = comparison_of(record).cloned();
    Handles {
        request: record.request.clone(),
        comparison,
    }
}

/// Records a comparison handle against a flow already in the registry.
///
/// Only ever called with the handle upstream just produced for that flow,
/// and only for a flow this process registered, so a miss here means the
/// registry released the flow between two calls about it -- which the
/// eviction rule cannot do, since it only runs while registering. Ignored
/// rather than reported: there is no caller mistake to report, and the next
/// call would recover the same handle from the request anyway.
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
                .ok_or(MachineError::MalformedIdentifier {
                    detail: "no such device".to_string(),
                })?;

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
/// Either side may call this. If both do, upstream settles which one's
/// comparison survives; the loser's is dropped and the flow carries on, so
/// this is safe to call from a product that cannot tell who got there
/// first.
pub async fn begin_comparison(flow: &FlowId) -> Result<(), MachineError> {
    let handles = handles(flow).await?;
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
    let mut record = FlowRecord {
        request: handles.request,
        comparison: handles.comparison,
    };
    Ok(stage_of(&mut record))
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
