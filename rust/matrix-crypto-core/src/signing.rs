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
//! 1. **Have we asked?** Has a `/keys/query` naming this account been sent
//!    and answered in this process. Tracked by `session.rs`, which is the
//!    only place that can know it, and recorded when the *response* is
//!    accepted rather than when the request is handed out.
//! 2. **What did the answer say?** Does this machine now hold a public
//!    identity for the account. Read from the store, where the answer to (1)
//!    put it.
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
//! status crosses this library's boundary, so a caller that reports a
//! failed query's body as a success supplies that fact falsely and the gate
//! believes it. `session::mark_request_sent` refuses the two failure shapes
//! a body can carry -- a standard Matrix error and an authentication
//! challenge -- and the key query's own response parse rejects anything
//! that is not that endpoint's shape, so a proxy's HTML page does not get
//! through either.
//!
//! What does still lift the gate, all of it a body no conformant homeserver
//! sends: `{}`, an empty body (ruma substitutes `{}` for it before
//! parsing), a JSON error object carrying no top-level `errcode` such as a
//! gateway's `{"error":"Bad Gateway"}`, and a JSON array. Each is something
//! serde can read as an all-optional response shape, and only the HTTP
//! status separates them from a real answer. Fact (1) is also "asked at some point in this
//! process", not "asked recently": a bootstrap long after the answer
//! decides on stale information.
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

use matrix_sdk_crypto::OlmMachine;

use crate::machine::{with_machine, MachineError};

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

async fn read_status(machine: &OlmMachine) -> Result<IdentityStatus, MachineError> {
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
/// # The rule
///
/// Served when this process has asked *and* either the account has no
/// identity or this device holds the one it has. Refused otherwise, with
/// the two refusals kept apart because their remedies are different: ask
/// again, versus join the identity that already exists.
fn may_mint(status: &IdentityStatus) -> Result<(), MachineError> {
    if !status.account_keys_fetched {
        return Err(MachineError::AccountKeysNotFetched);
    }
    if status.identity_known && !status.private_keys_held {
        return Err(MachineError::IdentityAlreadyExists);
    }
    Ok(())
}

/// What this library will say about the account's signing identity right
/// now. Reads only; asks the server nothing and mints nothing.
pub async fn identity_status() -> Result<IdentityStatus, MachineError> {
    with_machine(|machine| Box::pin(read_status(machine))).await?
}

/// Publishes this account's signing identity, minting one first if the
/// account provably has none.
///
/// Safe to call on every launch. The first call in a process is normally
/// refused once, with the key query that lifts the refusal already queued;
/// the call after that answer is served, and further calls in the same
/// process republish the identity this device holds rather than minting a
/// second one. What it will not do is mint over an identity the account
/// already has -- see this module's own documentation for why that is the
/// point rather than a precaution.
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
/// and that includes the 401 challenge above. Report nothing for the
/// challenge and report the eventual success. This matters more here than
/// anywhere else on the surface: a failed key query reported as a success
/// is read by the gate below as "the server answered and this account has
/// no identity", which is the one fact that authorises a mint; and the
/// signing-keys upload's success response is an empty object, so a reported
/// challenge would mark an identity published that never was.
///
/// That call refuses a standard error body and a challenge on sight, and
/// how much else it catches differs by request. For the key query, whose
/// response type has fields, a body that is not that endpoint's shape --
/// a proxy's HTML page, a truncated response -- is rejected by the parse
/// behind it. For the signing-keys upload, whose success response is
/// `Response {}`, ruma emits no body parse at all, so **anything that is
/// not a Matrix error or a challenge is accepted**, including bytes that
/// are not JSON. No HTTP status crosses this library's boundary, so what
/// gets past that is yours to prevent by branching on the status. See
/// `session::refuse_a_non_response` for the mechanism and the exact
/// division.
///
/// # Refusals
///
/// [`MachineError::AccountKeysNotFetched`] means this process has not yet
/// asked the server about this account, so it cannot know whether minting
/// or republishing would destroy an existing identity. **This call queues
/// that key query before returning it**, so the remedy is the ordinary
/// loop: drain the pump, send, report sent, call this again. Holding the
/// private keys is not an exemption; `may_mint` says why.
///
/// [`MachineError::IdentityAlreadyExists`] means the answer named an
/// identity this device does not hold the private keys for. There is no
/// remedy through this call and there should not be: this device joins that
/// identity, it does not replace it.
pub async fn bootstrap_identity() -> Result<(), MachineError> {
    with_machine(|machine| {
        Box::pin(async move {
            let status = read_status(machine).await?;

            if let Err(refusal) = may_mint(&status) {
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

            // Queued in upstream's stated order, which is also the order
            // their sequence stamps put them in when the pump hands them
            // out. Two of the three are ordinary action requests; the
            // middle one is the request class the pump could not carry
            // until this milestone -- `AnyOutgoingRequest` has no variant
            // for that endpoint, so it can neither come out of
            // `outgoing_requests()` nor go into `queue_action_request`.
            if let Some(device_keys) = requests.upload_keys_req {
                crate::session::queue_action_request(device_keys);
            }
            crate::session::queue_signing_keys_request(requests.upload_signing_keys_req);
            crate::session::queue_action_request(requests.upload_signatures_req.into());

            Ok(())
        })
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate's rule, stated once and checked against every combination it
    /// can face, without a store or a machine in sight.
    ///
    /// The integration tests under `tests/` drive the two refusals through
    /// the real surface, which is what proves they are reachable. This
    /// covers what those cannot reach cheaply: that **holding the private
    /// keys overrides neither refusal**, so a device whose store predates an
    /// identity reset elsewhere is still made to ask before it republishes;
    /// and that no combination of the three flags produces a fourth outcome.
    #[test]
    fn minting_is_served_only_when_the_account_provably_has_no_identity() {
        for account_keys_fetched in [false, true] {
            for identity_known in [false, true] {
                for private_keys_held in [false, true] {
                    let status = IdentityStatus {
                        account_keys_fetched,
                        identity_known,
                        private_keys_held,
                    };
                    let expected = if !account_keys_fetched {
                        Err(MachineError::AccountKeysNotFetched)
                    } else if identity_known && !private_keys_held {
                        Err(MachineError::IdentityAlreadyExists)
                    } else {
                        Ok(())
                    };
                    assert_eq!(may_mint(&status), expected, "for {status:?}");
                }
            }
        }

        // Named separately rather than left to be read out of the loop
        // above, because they are the two rows the milestone exists for.
        //
        // Asked nothing, hold nothing, know nothing: a gate written as "is
        // the local identity empty" serves this row.
        assert_eq!(
            may_mint(&IdentityStatus {
                account_keys_fetched: false,
                identity_known: false,
                private_keys_held: false,
            }),
            Err(MachineError::AccountKeysNotFetched)
        );

        // Asked nothing, but holding a complete private identity: the row a
        // restored backup lands on. Serving it republishes keys the server
        // may already have replaced. This is the row the short-circuit this
        // gate used to have served without asking anything.
        assert_eq!(
            may_mint(&IdentityStatus {
                account_keys_fetched: false,
                identity_known: false,
                private_keys_held: true,
            }),
            Err(MachineError::AccountKeysNotFetched)
        );
    }
}
