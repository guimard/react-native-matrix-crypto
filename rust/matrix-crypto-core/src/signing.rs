//! This account's signing identity: reading whether it has one, and
//! publishing one when it safely can.
//!
//! An account's signing identity is what lets one device vouch for another
//! without a person comparing anything, and what lets a decrypted event say
//! who sent it rather than only which key it arrived under. Every device of
//! the account signs into it; other users verify the account once instead of
//! device by device.
//!
//! # The whole reason this module is not a one-line wrapper
//!
//! Upstream's `bootstrap_cross_signing(false)` is safe **and** destructive,
//! depending entirely on when it is called:
//!
//! * Called on a device that already holds the complete private identity, it
//!   is idempotent *locally* -- it re-derives the publication of what is
//!   already there and yields the same master key. What it publishes may
//!   still be wrong: a store restored from a backup holds a complete
//!   identity the server has already replaced, and republishing it puts the
//!   old one back over the new. Local idempotence is not safety.
//! * Called on a device whose private identity is incomplete, it **mints a
//!   new one** (`matrix-sdk-crypto-0.18.0/src/machine/mod.rs:676` branches on
//!   `identity.is_empty()`, and a partial identity counts as empty). If the
//!   account already had an identity, publishing the new one replaces it and
//!   resets the trust of every device and every user who had verified the
//!   old one.
//!
//! The second case is not exotic. It is the ordinary shape of a fresh login:
//! new device, empty store, an account that has been in use for years. There
//! is no error and no warning, and the damage is to other people's trust in
//! this user rather than to anything this process can afterwards detect.
//!
//! # The gate, and the question it is careful not to ask
//!
//! The tempting gate is "is the local identity empty". It refuses nothing:
//! it is the same question upstream already asks before minting, so every
//! call it would refuse is a call upstream already treats as a mint.
//!
//! The gate here is two different facts, and both are needed:
//!
//! 1. **Have we asked, and does upstream now know?** Has a `/keys/query`
//!    naming this account been sent and answered in this process, and did
//!    the answer leave upstream's store able to say whether the account has
//!    an identity. Tracked by `session.rs`, which is the only place that can
//!    know it, and recorded when the *response* is accepted rather than when
//!    the request is handed out.
//! 2. **What did the answer say?** Does this machine now hold a public
//!    identity for the account. Read from the store, where the answer to (1)
//!    put it.
//!
//! Fact (1) used to stop at "and was answered", then at "and the answer
//! named this account", and both were defeated by answers upstream had
//! dropped. It is the same store read in both facts now, asked at two
//! different moments and for two different reasons, which is why they are
//! still two facts and not one.
//!
//! Nothing is served before (1), **including a republication by a device
//! that holds the private keys**, because that is exactly the restored-backup
//! case above and only a key query can tell it apart from an ordinary
//! relaunch. Given (1), the call is served when the account has no identity
//! or this device holds the one it has. "Not asked" and "asked, and there is
//! one this device does not hold" are different refusals with different
//! remedies, and [`MachineError::AccountKeysNotFetched`] /
//! [`MachineError::IdentityAlreadyExists`] keep them apart.
//!
//! # What the gate cannot check
//!
//! Fact (1) is "a key query was reported to us as having succeeded". No HTTP
//! status crosses this library's boundary on that call, so a caller that
//! reports a failed query's body as a success supplies that fact falsely and
//! the gate believes it.
//!
//! `session::mark_request_sent` refuses every body it can show is not an
//! answer, and accepts every body shaped like one. **The exact division, and
//! why the remainder cannot be closed from a body, is stated once at
//! `session::refuse_a_non_response` and deliberately not repeated here.**
//! What a maintainer of this file needs from it is the consequence: a body
//! shaped like a key query answer is *accepted*, whatever status it actually
//! arrived with.
//!
//! **Accepted is no longer the same as lifting this gate**, and that is the
//! narrower thing to know. `session::answer_about_this_account` additionally
//! requires that, once upstream has consumed the accepted body, upstream's
//! own store **says whether this account has an identity**. Either the
//! answer asserted a cross-signing key for the account and upstream now
//! holds the identity it asserted, or the answer asserted none and named the
//! account under `device_keys`. So an answer about other users, a body whose
//! only substance is a `failures` map, the empty object, and an answer
//! carrying this account's own published master key that upstream could not
//! assemble into an identity all pass `mark_request_sent` and leave this
//! gate shut.
//!
//! That last one is why the rule reads upstream rather than the body.
//! Upstream needs a master key **and** a self-signing key to store an
//! identity, and a user-signing key too when the user is our own; anything
//! short of that it drops with a `warn!` and no error. Measured against a
//! live Synapse 1.159.0: an account that had published a master key alone
//! answered its own key query with a body carrying that key, a rule that
//! read the body's map keys lifted this gate, and the bootstrap minted a
//! second identity over the published one. Flipping one character of one
//! base64 signature in an otherwise correct answer did the same.
//!
//! Fact (1) can also be **unsettled**: the answer arrived, was accepted, and
//! left upstream still not knowing. `IdentityStatus`'s
//! `account_keys_answer_unsettled` is what says so, and its own doc comment
//! says what a product does about it. Without it the refusal below is
//! indistinguishable from "nobody has asked", whose remedy is to ask again,
//! which against a server that omits the account is a loop with no end.
//!
//! Reporting nothing at all is equally safe here: the gate needs a positive
//! mark to open, so silence leaves it shut. A caller that got a non-2xx
//! should still say so through `session::mark_request_failed`, which is what
//! keeps a refused request resolvable and is the only way to close the same
//! collision on the signing-keys upload, where `{}` really is the whole
//! success response.
//!
//! Fact (1) is also "asked at some point in this process", not "asked
//! recently": a bootstrap long after the answer decides on stale
//! information.
//!
//! # This library never sees a credential
//!
//! Publishing the identity needs user-interactive authentication at the
//! homeserver, and upstream surfaces none of it -- its own request type is
//! three key fields with no `auth`, while the real endpoint's request has
//! one. So the product owns that loop: send the body this module queues,
//! read the challenge out of the refusal, ask its user, send the same body
//! again with `auth` merged into it. There is deliberately no `auth`
//! parameter on [`bootstrap_identity`], and the reason is not squeamishness:
//! the challenge is only known *after* the first request is refused, so any
//! up-front credential parameter would have to be guessed before the server
//! has said what it wants. `session::mark_request_sent` looks its entry up
//! without removing it, so the retry is an ordinary second send of the same
//! pending request.

use std::sync::atomic::{AtomicBool, Ordering};

use matrix_sdk_crypto::OlmMachine;

use crate::machine::{with_machine, MachineError};

/// Whether the account's private signing keys were held the last time
/// anything looked, so that an arrival can be told from a standing fact.
///
/// Process-wide, like the machine and the flow registry, and deliberately
/// **not** persisted: it is not a record of what this account has, which is
/// [`IdentityStatus::private_keys_held`]'s job, but of what this process has
/// already reported. Seeded from the store the moment a machine is created
/// (`machine::build`), so a relaunch of a device that already holds the keys
/// starts out having nothing new to say.
static PRIVATE_KEYS_HELD: AtomicBool = AtomicBool::new(false);

/// Records what a machine holds at the moment it is created or reopened.
///
/// Called from `machine::build` and from its test reset, and from nowhere
/// else: every other update goes through [`note_private_keys_held`], which
/// is the one that decides whether anything is announced.
pub(crate) fn seed_private_keys_held(held: bool) {
    PRIVATE_KEYS_HELD.store(held, Ordering::SeqCst);
}

/// Records what the machine holds now, and answers whether that is news.
///
/// **True exactly once per arrival.** The two ways a device comes to hold
/// the account's private signing keys are [`bootstrap_identity`], which
/// mints them, and secret gossip from another of our own devices, which
/// lands inside `receive_sync_changes` after this device has verified
/// itself against one of them. Neither is special-cased: the rule is that
/// the first look which finds the keys present, after a look that found
/// them absent, is the arrival.
///
/// `false` is stored as faithfully as `true`, and that is not symmetry for
/// its own sake. Upstream drops a private identity that a key query has
/// contradicted (`identities/manager.rs:418-443`), so the keys really can
/// go away; recording that is what lets a later arrival be announced rather
/// than swallowed as "already reported".
///
/// The caller decides what to do with a `true`. `verification::announce_state_changes`
/// is the only one, and it only ever asks while somebody is listening, so
/// an arrival nobody was subscribed for leaves this latch alone and is
/// announced on the first sync after somebody subscribes.
pub(crate) fn note_private_keys_held(held_now: bool) -> bool {
    held_now && !PRIVATE_KEYS_HELD.swap(held_now, Ordering::SeqCst)
}

/// What this library will say about the account's signing identity.
///
/// Three independent facts, none of which implies another, and the pair that
/// looks redundant is the pair that matters: `identity_known == false` means
/// something completely different depending on `account_keys_fetched`. With
/// it false, it means "nobody has asked". With it true, it means "the server
/// says there is none". Only the second is a basis for minting one, which is
/// why both are reported rather than a single collapsed answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityStatus {
    /// Whether a key query naming this account has been sent **and
    /// answered** in this process.
    ///
    /// Not persisted: a process that has just reopened a store has asked
    /// nothing yet, whatever the process before it did, and the account may
    /// have gained an identity in between. False here is not a claim that
    /// the account has no identity; it is a refusal to guess.
    pub account_keys_fetched: bool,
    /// Whether this machine holds a public signing identity for the account.
    ///
    /// Read only alongside `account_keys_fetched`. A bootstrap sets this
    /// true as a side effect of minting, so it is also how a caller sees
    /// that its own bootstrap took effect.
    pub identity_known: bool,
    /// Whether this device holds the account's complete private signing
    /// keys, and can therefore sign with the identity rather than only
    /// recognise it.
    ///
    /// A device that has joined the identity by self-verifying, or restored
    /// it from server-side storage, holds them too. Incomplete counts as
    /// false: upstream regenerates a partial private identity wholesale.
    ///
    /// **True does not mean the server agrees.** Until `account_keys_fetched`
    /// is also true, these keys may belong to an identity the account has
    /// since replaced -- a restored backup holds a complete one that is
    /// simply out of date. Upstream drops such keys when a key query
    /// contradicts them (`identities/manager.rs:418-443`), so this field is
    /// only trustworthy alongside that one.
    pub private_keys_held: bool,
    /// Whether a key query about this account was answered, and the answer
    /// left the library still unable to say whether the account has an
    /// identity.
    ///
    /// **Read this when `account_keys_fetched` is false, and only then.**
    /// The two together say which of two situations a refusal is in, and
    /// they have different remedies:
    ///
    /// * Both false: nobody has asked yet. The remedy is the documented one
    ///   -- drain `crate::take_outgoing_requests`, send what it hands back,
    ///   report each with `crate::mark_request_sent`, call again.
    /// * This true: a key query naming this account was sent, the server
    ///   answered, the answer was accepted, and upstream still does not know
    ///   whether the account has an identity. **Asking again will do the
    ///   same thing.** Either the answer did not cover this account -- which
    ///   the Matrix specification prescribes for a user a reachable server
    ///   does not know, and which a mixed-case server name in this machine's
    ///   own account id also produces, because a homeserver then treats the
    ///   account as remote -- or it asserted cross-signing keys for the
    ///   account that upstream could not read.
    ///
    /// So the action on this field is to stop looping and look at the
    /// account id: compare the `user_id` this machine was created with
    /// against the canonical one `/login` returned. Nothing is destroyed
    /// while this is true, and nothing will be: a refusal to mint is the
    /// safe direction, and this field is what stops the refusal from being
    /// silent.
    ///
    /// Never true alongside `account_keys_fetched`. Once upstream knows, a
    /// later answer that settles nothing does not un-know it.
    pub account_keys_answer_unsettled: bool,
}

/// Errors must not carry an identifier or key material, so an upstream store
/// failure reports its shape and nothing else -- the same rule and the same
/// fixed string as `machine.rs`'s `store_error_detail`, `identity.rs`'s
/// `store_failed` and `verification.rs`'s.
fn store_failed() -> MachineError {
    MachineError::Store {
        detail: "the crypto store could not be opened".to_string(),
    }
}

pub(crate) async fn read_status(machine: &OlmMachine) -> Result<IdentityStatus, MachineError> {
    // `None` as the timeout, not a duration: with `Some`, upstream waits for
    // an in-flight key query for this account to land
    // (`wait_if_user_pending`, `machine/mod.rs:2646`), and a read of what is
    // known *now* must not block on a request the caller may never send.
    let identity_known = machine
        .get_identity(machine.user_id(), None)
        .await
        .map_err(|_upstream| store_failed())?
        .is_some();

    Ok(IdentityStatus {
        account_keys_fetched: crate::session::account_keys_answered(),
        identity_known,
        private_keys_held: machine.cross_signing_status().await.is_complete(),
        account_keys_answer_unsettled: crate::session::account_keys_answer_unsettled(),
    })
}

/// Whether [`bootstrap_identity`] may proceed, given what is known.
///
/// The single place the rule lives, so [`identity_status`] and
/// [`bootstrap_identity`] cannot come to disagree about it.
///
/// # Nothing is served before the server has been asked
///
/// The check on `account_keys_fetched` comes first and has no exception,
/// **including for a device that already holds the private keys.** An
/// earlier version short-circuited on `private_keys_held`, reasoning that
/// upstream cannot mint when the private identity is complete
/// (`cross_signing_status().is_complete()` is exactly the negation of the
/// `PrivateCrossSigningIdentity::is_empty` upstream branches on --
/// `olm/signing/mod.rs:99-138`, `machine/mod.rs:676`) and that a key query
/// therefore could not change the outcome.
///
/// **It can change the outcome, and the case where it does is the case that
/// matters.** A store restored from a backup, or one whose account had its
/// identity reset from another device, holds a *complete* private identity
/// the server has already replaced. Republishing it puts the stale identity
/// back over the newer one, which resets the trust of every device and every
/// user who had verified the newer one -- the same destruction this gate
/// exists to prevent, arrived at from the other direction. Upstream itself
/// only notices on a key query: `IdentityManager::check_private_identity`
/// calls `clear_if_differs` and drops the stale private keys
/// (`identities/manager.rs:418-443`), after which `private_keys_held` is
/// false, `identity_known` is true, and the rule below refuses correctly.
///
/// The cost is one key query per process before its first bootstrap, not one
/// per bootstrap: `account_keys_fetched` stays true for the process
/// lifetime once an answer has been accepted. A caller pays the same
/// drain-send-report round it already pays on a fresh login, and pays it
/// uniformly rather than only in the cases that looked dangerous.
///
/// # The rule, and why it is now two rules
///
/// This used to be one predicate for two acts. Given the gate, it served a
/// call that would **republish** the identity this device holds, and it
/// served a call that would **create** the account's first identity, and a
/// caller could not say which of the two it meant. `bootstrap_identity` was
/// documented as safe to call on every launch, so the create was reached by
/// the ordinary launch path of every device.
///
/// That is what made the timing race destructive. Measured against a live
/// continuwuity: a device queried its own fresh account, the server honestly
/// answered "no identity" because at that instant there was none, another
/// device of the same account published one in the window, and the first
/// device's launch-time `bootstrap_identity` then minted a second identity
/// over it. **No misbehaving server is involved.** The answer was true when
/// it was sent, and no rule reading one answer can tell it from an answer
/// that is still true when it is reported.
///
/// So the second condition is not a better gate. It is that **creating an
/// identity is a different act from publishing one, and the caller has to
/// say which it means.** The library cannot know whether this account is
/// meant to be getting its first identity right now; the product can, and
/// it is the only party that can. [`may_publish`] governs the call a product
/// makes on every launch and it can never create anything; [`may_create`]
/// governs the one destructive act and nothing reaches it by default.
///
/// # `may_publish`
///
/// Served when this process has asked, the account has an identity, and this
/// device holds its private keys. The three refusals are kept apart because
/// their remedies differ: ask again; create one; join the one that exists.
fn may_publish(status: &IdentityStatus) -> Result<(), MachineError> {
    if !status.account_keys_fetched {
        return Err(MachineError::AccountKeysNotFetched);
    }
    if !status.identity_known {
        return Err(MachineError::IdentityNotKnown);
    }
    if !status.private_keys_held {
        return Err(MachineError::IdentityAlreadyExists);
    }
    Ok(())
}

/// Whether [`create_identity`] may mint the account's first identity.
///
/// Served when this process has asked and the answer said the account has
/// none. `identity_known` refuses whether or not this device holds the
/// private keys, and that is wider than the old rule on purpose: with an
/// identity known, there is nothing here to create, and the two things a
/// caller might have wanted are `bootstrap_identity` (publish the one this
/// device holds) and `crate::request_self_flow` (join the one it does not).
fn may_create(status: &IdentityStatus) -> Result<(), MachineError> {
    if !status.account_keys_fetched {
        return Err(MachineError::AccountKeysNotFetched);
    }
    if status.identity_known {
        return Err(MachineError::IdentityAlreadyExists);
    }
    Ok(())
}

/// What this library will say about the account's signing identity right
/// now. Reads only; asks the server nothing and mints nothing.
pub async fn identity_status() -> Result<IdentityStatus, MachineError> {
    with_machine(|machine| Box::pin(read_status(machine))).await?
}

/// Publishes the signing identity **this device already holds**.
///
/// Safe to call on every launch, and that is now true without qualification:
/// **this call cannot create an identity.** It republishes the one this
/// device holds the private keys for, and refuses every other state.
///
/// # What changed, and why the every-launch call gave up its other job
///
/// This used to mint the account's first identity when it judged the account
/// had none. That judgement rests on one `/keys/query` answer, and an answer
/// is only ever true of the instant the server sent it. Measured against a
/// live continuwuity: a device asked about its own fresh account, the server
/// honestly answered "no identity" because at that instant there was none,
/// another device of the same account published one in the window, and this
/// call then minted a second identity over it. The product had done nothing
/// wrong; it had called the function this library tells it to call on every
/// launch.
///
/// No rule reading one answer can tell a true "no identity" from one that
/// was true a moment ago, so the fix is not a better gate. It is that the
/// destructive act now has its own name and nothing arrives at it by
/// default: [`create_identity`] is the only call that mints, and a product
/// reaches it only by deciding to. See [`may_publish`] for the rule and
/// [`may_create`] for the other one.
///
/// The first call in a process is still normally refused once, with the key
/// query that lifts the refusal already queued, and the call after that
/// answer is served.
///
/// # What a caller must do next
///
/// Nothing here reaches the network; this library performs no request. On
/// success, drain [`crate::take_outgoing_requests`] and send what it hands
/// back **in the order it hands it back**, reporting each with
/// [`crate::mark_request_sent`]. The order that matters is device keys,
/// then `signing_keys_upload`, then `signature_upload`, because a signature
/// may reference a key that is not published yet.
///
/// **Four of the batch's entries come from this call, and the batch is
/// longer than four.** Do not assert a length. Observed after a served
/// bootstrap on a fresh machine:
/// `["keys_upload", "signing_keys_upload", "signature_upload",
/// "keys_upload", "keys_query"]` -- five, because the pump also carries
/// whatever else upstream owed at that moment, which here is a key query.
///
/// The four that belong to the bootstrap are a `keys_upload` this call
/// queued, the `signing_keys_upload`, the `signature_upload`, and then a
/// *second* `keys_upload` under a different id carrying the same device
/// keys. The duplicate is upstream's own standing "these device keys are
/// not published yet" request, which `outgoing_requests()` offers
/// independently of the copy `bootstrap_cross_signing` hands back. Sending
/// both is harmless -- the endpoint is idempotent and the second is a no-op
/// at the server -- and the copy this call queues is the one that has to
/// exist, because only a queued request carries a sequence stamp early
/// enough to sort ahead of the signing keys. A caller that would rather not
/// send the same twelve kilobytes twice may send the first `keys_upload`,
/// report it, and find the duplicate absent from the next batch.
///
/// The `signing_keys_upload` request is the one that needs user-interactive
/// authentication. Expect the first attempt to be refused with a challenge,
/// merge an `auth` object into the body, and send it again.
///
/// **The id survives any number of refused attempts, but not another
/// bootstrap.** Nothing about failing an attempt consumes the request:
/// [`crate::mark_request_sent`] removes an entry only on success, so a
/// caller may loop on a 401 as long as its user needs. What does retire the
/// id is calling this function again and draining the pump again, because a
/// second bootstrap re-derives the same three keys and the fresh
/// publication supersedes the stale one -- without that, the pump's pending
/// map would grow by one entry for every bootstrap-and-drain cycle in the
/// process. A held id then reports
/// [`crate::SessionError::UnknownRequest`], which fails closed and costs
/// nothing to recover from: the body is identical, so drain again and use
/// the id from the newer batch. If a user-interactive loop is in flight, do
/// not call this again until it finishes.
///
/// # Report only what a success returned
///
/// **Never report a non-2xx body through [`crate::mark_request_sent`]**,
/// and that includes the 401 challenge above. Send it to
/// [`crate::mark_request_failed`] instead, or report nothing at all, and
/// report the eventual success through `mark_request_sent`. This matters
/// more here than anywhere else on the surface: a failed key query reported
/// as a success is read by the gate below as "the server answered and this
/// account has no identity", which is the one fact that authorises a mint;
/// and the signing-keys upload's success response is an empty object, so a
/// reported challenge would mark an identity published that never was.
///
/// `mark_request_sent` refuses on sight every body it can show is not an
/// answer, and accepts every body shaped like one. **What that shape is, and
/// why the remainder cannot be closed from a body, is stated once at
/// `session::refuse_a_non_response`**; it is not restated here.
///
/// The part that bites at this call is that the empty object is inside the
/// shape for both requests above, and is the whole success response of the
/// signing-keys upload. Only the status tells that answer from a refusal,
/// and the status is yours. See [`crate::mark_request_failed`] for where a
/// non-2xx goes.
///
/// # Refusals
///
/// [`MachineError::AccountKeysNotFetched`] means this process cannot yet say
/// what identity this account has, so it cannot know whether minting or
/// republishing would destroy an existing one. **This call queues that key
/// query before returning it**, so the usual remedy is the ordinary loop:
/// drain the pump, send, report sent, call this again. Holding the private
/// keys is not an exemption; [`may_publish`] says why.
///
/// **That loop has a case where it never terminates, and this variant alone
/// does not say which case you are in.** Read
/// [`IdentityStatus::account_keys_answer_unsettled`]: false means nobody has
/// asked and the loop works; true means a query was sent, the server
/// answered, and the answer settled nothing, so the next round will do
/// exactly what the last one did. That field's own doc comment says what to
/// do instead, and `tests/identity_bootstrap_unsettled_answer.rs` drives
/// five rounds of the loop to show it. Splitting the two into separate
/// variants would be the better surface; it is not done here because the
/// wire ordinals after `MachineError`'s last variant are reserved by work in
/// flight, and a variant appended into that range would be misdecoded by
/// bindings generated before it.
///
/// [`MachineError::IdentityAlreadyExists`] means the answer named an
/// identity this device does not hold the private keys for. There is no
/// remedy through this call and there should not be: this device joins that
/// identity, it does not replace it, and [`crate::request_self_flow`] is how.
///
/// [`MachineError::IdentityNotKnown`] is the refusal this call gained, and
/// it is the one an existing product will meet first: the server was asked
/// and named no identity for this account, so there is nothing here to
/// publish. It is not a failure and nothing is wrong; it is this call
/// declining to make the decision that used to be made silently. The remedy
/// is [`create_identity`], and a product should reach it having decided that
/// this account is meant to be getting its first identity now.
pub async fn bootstrap_identity() -> Result<(), MachineError> {
    with_machine(|machine| {
        Box::pin(async move {
            let status = read_status(machine).await?;

            if let Err(refusal) = may_publish(&status) {
                if refusal == MachineError::AccountKeysNotFetched {
                    // Queued *by* the refusal, so the refusal is recoverable
                    // rather than a dead end. Upstream volunteers an
                    // own-account key query only while the account is not
                    // yet tracked ("We always want to track our own user",
                    // `identities/manager.rs:836-852`), and it will not
                    // re-dirty an account it is already tracking:
                    // `update_tracked_users` inserts into a set and only
                    // flags what was newly inserted (`store/mod.rs:258-273`).
                    // So on a second process for the same store, or on any
                    // process that shared a key before bootstrapping,
                    // nothing would ever ask again and this refusal would be
                    // permanent. Asking out-of-band costs one request and
                    // removes that trap entirely. It is covered by
                    // `tests/identity_bootstrap_recovery.rs`, which
                    // constructs the case upstream volunteers nothing in.
                    let (id, request) =
                        machine.query_keys_for_users(std::iter::once(machine.user_id()));
                    crate::session::queue_account_key_query(id, request);
                }
                return Err(refusal);
            }

            let requests = machine
                .bootstrap_cross_signing(false)
                .await
                .map_err(|_upstream| store_failed())?;

            queue_publication(requests);

            Ok(())
        })
    })
    .await?
}

/// Queues what a publication of this account's identity has to send, in
/// upstream's stated order, which is also the order their sequence stamps
/// put them in when the pump hands them out.
///
/// Two of the three are ordinary action requests; the middle one is the
/// request class the pump could not carry until M4 -- `AnyOutgoingRequest`
/// has no variant for that endpoint, so it can neither come out of
/// `outgoing_requests()` nor go into `queue_action_request`.
///
/// Shared by [`bootstrap_identity`] and [`create_identity`] rather than
/// written twice: the two calls differ in what they are allowed to do, not
/// in what they send, and a copy would let the orders drift apart.
fn queue_publication(requests: matrix_sdk_crypto::CrossSigningBootstrapRequests) {
    if let Some(device_keys) = requests.upload_keys_req {
        crate::session::queue_action_request(device_keys);
    }
    crate::session::queue_signing_keys_request(requests.upload_signing_keys_req);
    crate::session::queue_action_request(requests.upload_signatures_req.into());
}

/// Creates this account's **first** signing identity.
///
/// **This is the one destructive call on this surface, and it is destructive
/// exactly when it is wrong.** An identity minted over one the account
/// already has replaces it, and replacing it resets the trust of every
/// device and every person who ever verified the old one. There is no undo,
/// and nothing afterwards can detect it.
///
/// It exists as its own call because that damage was previously reachable
/// from [`bootstrap_identity`], which this library tells a product to call
/// on every launch. See that function for the measured race that made an
/// honest homeserver enough to do it.
///
/// # What a caller must hold before calling this
///
/// The library's own precondition is [`may_create`]: this process has asked
/// the server, and the answer said the account has no identity.
/// **That precondition is necessary and it is not sufficient**, and this
/// paragraph is the whole reason the call is separate.
///
/// A `/keys/query` answer is only ever true of the instant the server sent
/// it. Between that instant and this call, another device of the same
/// account can publish an identity, and no answer already in hand can say
/// so. Measured on a live homeserver, with no misbehaviour anywhere: the
/// server answered "no identity" honestly, a second device published one,
/// and a mint followed. So the caller has to supply the fact the library
/// cannot: **that this account is meant to be getting its first identity
/// now.** A product knows things the library does not -- that the user has
/// just created the account, that this is the sign-up flow rather than a
/// relaunch, that no other session is listed on the account, that a person
/// has been asked and said yes. Calling this on every launch, or as the
/// automatic remedy for [`MachineError::IdentityNotKnown`], puts that
/// decision back where it was and the race back with it.
///
/// # What this does about the window it cannot close
///
/// It queues a fresh account `/keys/query` alongside the publication, so the
/// product's ordinary pump loop asks the server once more straight after.
/// That does not prevent the race: the publication is handed out first and a
/// product that sends it has already sent it. What it prevents is the state
/// the race otherwise leaves behind, which was measured and is worse than it
/// looks -- a device holding an identity the account does not have, reporting
/// `identity_known` and `private_keys_held` like a healthy one, and **never
/// asking again**, because a served publication queues no query and upstream
/// volunteers none for an account it already tracks. With the query queued,
/// the next answer carries the identity the account really has, upstream
/// drops the private keys that disagree with it, and this device correctly
/// reports `IdentityAlreadyExists` and joins instead.
///
/// # What a caller must do next
///
/// The same as [`bootstrap_identity`]: drain [`crate::take_outgoing_requests`]
/// and send what it hands back in the order it hands it back, reporting each
/// with [`crate::mark_request_sent`]. Everything that call documents about
/// the user-interactive authentication loop, about reporting only what a 2xx
/// returned, and about the batch being longer than the requests this call
/// owns, applies here unchanged and is not repeated.
///
/// # Refusals
///
/// [`MachineError::AccountKeysNotFetched`] means this process cannot yet say
/// what identity this account has. As with `bootstrap_identity`, this call
/// queues that key query before returning, and
/// [`IdentityStatus::account_keys_answer_unsettled`] says whether the remedy
/// is to pump and call again or to stop and check the account id.
///
/// [`MachineError::IdentityAlreadyExists`] means the account already has an
/// identity, so there is nothing here to create. It is returned whether or
/// not this device holds the private keys, because neither case wants this
/// call: holding them, the call is [`bootstrap_identity`]; not holding them,
/// it is [`crate::request_self_flow`].
pub async fn create_identity() -> Result<(), MachineError> {
    with_machine(|machine| {
        Box::pin(async move {
            let status = read_status(machine).await?;

            if let Err(refusal) = may_create(&status) {
                if refusal == MachineError::AccountKeysNotFetched {
                    // Queued by the refusal, for `bootstrap_identity`'s
                    // reason, which its own comment states in full.
                    let (id, request) =
                        machine.query_keys_for_users(std::iter::once(machine.user_id()));
                    crate::session::queue_account_key_query(id, request);
                }
                return Err(refusal);
            }

            let requests = machine
                .bootstrap_cross_signing(false)
                .await
                .map_err(|_upstream| store_failed())?;

            queue_publication(requests);

            // The confirming query. Queued *after* the publication, so the
            // pump hands the publication out first and the ordinary
            // send-and-report loop asks the server again immediately after.
            // See this function's own section on the window: this is
            // detection, not prevention, and it is stated as such.
            let (id, request) = machine.query_keys_for_users(std::iter::once(machine.user_id()));
            crate::session::queue_account_key_query(id, request);

            Ok(())
        })
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two rules, stated once and checked against every combination they
    /// can face, without a store or a machine in sight.
    ///
    /// The integration tests under `tests/` drive the refusals through the
    /// real surface, which is what proves they are reachable. This covers
    /// what those cannot reach cheaply: that no combination of the flags
    /// produces an outcome neither rule names, and that
    /// `account_keys_answer_unsettled` **decides nothing** in either. That
    /// last one is the point of running the fourth flag through the loop: it
    /// is a diagnosis for a caller, not a second gate, and a rule that let it
    /// serve anything would be the whole defect back under a new name.
    ///
    /// **The pair is asserted together, and the property that matters is a
    /// property of the pair**: for every one of the sixteen states, at most
    /// one of the two calls is served. Publishing and creating are different
    /// acts on the same account, and a state that served both would mean the
    /// split bought nothing.
    #[test]
    fn publishing_and_creating_are_served_in_states_that_never_overlap() {
        let mut both_served = Vec::new();
        for account_keys_fetched in [false, true] {
            for identity_known in [false, true] {
                for private_keys_held in [false, true] {
                    for account_keys_answer_unsettled in [false, true] {
                        let status = IdentityStatus {
                            account_keys_fetched,
                            identity_known,
                            private_keys_held,
                            account_keys_answer_unsettled,
                        };

                        let publish = if !account_keys_fetched {
                            Err(MachineError::AccountKeysNotFetched)
                        } else if !identity_known {
                            Err(MachineError::IdentityNotKnown)
                        } else if !private_keys_held {
                            Err(MachineError::IdentityAlreadyExists)
                        } else {
                            Ok(())
                        };
                        assert_eq!(may_publish(&status), publish, "publish, for {status:?}");

                        let create = if !account_keys_fetched {
                            Err(MachineError::AccountKeysNotFetched)
                        } else if identity_known {
                            Err(MachineError::IdentityAlreadyExists)
                        } else {
                            Ok(())
                        };
                        assert_eq!(may_create(&status), create, "create, for {status:?}");

                        if publish.is_ok() && create.is_ok() {
                            both_served.push(status);
                        }
                    }
                }
            }
        }
        assert!(
            both_served.is_empty(),
            "no state may serve both publishing and creating; these did: {both_served:?}"
        );
    }

    /// The rows the milestone exists for, named rather than left to be read
    /// out of the loop above.
    #[test]
    fn neither_call_is_served_before_the_server_has_been_asked() {
        // Asked nothing, hold nothing, know nothing: a gate written as "is
        // the local identity empty" serves this row.
        let unasked = IdentityStatus {
            account_keys_fetched: false,
            identity_known: false,
            private_keys_held: false,
            account_keys_answer_unsettled: false,
        };
        assert_eq!(
            may_publish(&unasked),
            Err(MachineError::AccountKeysNotFetched)
        );
        assert_eq!(
            may_create(&unasked),
            Err(MachineError::AccountKeysNotFetched)
        );

        // Asked, answered, and the answer settled nothing: the row a server
        // that omits a user it does not know produces, the one a mixed-case
        // server name produces against a real Synapse, and now also the one a
        // restored store meets when an omitting answer contradicts what it
        // already holds. The refusal is the same and must be.
        let unsettled = IdentityStatus {
            account_keys_answer_unsettled: true,
            ..unasked
        };
        assert_eq!(
            may_publish(&unsettled),
            Err(MachineError::AccountKeysNotFetched)
        );
        assert_eq!(
            may_create(&unsettled),
            Err(MachineError::AccountKeysNotFetched)
        );
    }

    /// Asked, but the answer named an identity: **neither** call may mint.
    ///
    /// The row `create_identity` widened. The old single rule served this
    /// state whenever the private keys happened to be held, because it could
    /// not tell a republication from a creation. Now `bootstrap_identity`
    /// serves it, as the republication it is, and `create_identity` refuses
    /// it, because there is nothing here to create.
    #[test]
    fn an_account_that_already_has_an_identity_is_never_created_over() {
        for private_keys_held in [false, true] {
            let known = IdentityStatus {
                account_keys_fetched: true,
                identity_known: true,
                private_keys_held,
                account_keys_answer_unsettled: false,
            };
            assert_eq!(
                may_create(&known),
                Err(MachineError::IdentityAlreadyExists),
                "creating over a known identity is the destruction this \
                 module exists to prevent, and holding the private keys is \
                 not an exemption from it: {known:?}"
            );
        }
    }

    /// Asked, and the answer said the account has none: **only** creating.
    ///
    /// The mirror of the row above, and the one that says the every-launch
    /// call gave up its other job. `bootstrap_identity` used to mint here.
    #[test]
    fn an_account_with_no_identity_is_published_by_nothing() {
        let none = IdentityStatus {
            account_keys_fetched: true,
            identity_known: false,
            private_keys_held: false,
            account_keys_answer_unsettled: false,
        };
        assert_eq!(
            may_publish(&none),
            Err(MachineError::IdentityNotKnown),
            "there is nothing to publish, and the call that used to mint here \
             is the one an honest server plus timing turned into a mint over \
             a published identity: {none:?}"
        );
        assert_eq!(may_create(&none), Ok(()));
    }
}
