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
//!   is idempotent -- it re-derives the publication of what is already there
//!   and yields the same master key. Safe to call on every launch.
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
//! Minting is served only on "asked, and the answer named none". "Not asked"
//! and "asked, and there is one" are different refusals with different
//! remedies, and [`MachineError::AccountKeysNotFetched`] /
//! [`MachineError::IdentityAlreadyExists`] keep them apart.
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
/// `private_keys_held` short-circuits everything, and that is not a
/// shortcut: it is the exact condition under which upstream cannot mint.
/// `cross_signing_status().is_complete()` is `has_master && has_user_signing
/// && has_self_signing`, and `PrivateCrossSigningIdentity::is_empty` -- the
/// flag upstream branches on -- is its negation, over the same object
/// (`olm/signing/mod.rs:99-138`, `machine/mod.rs:676`). So when this is
/// true, the call ahead is a republication of an identity this device
/// already holds and there is nothing to gate. Requiring a key query for it
/// would cost a round trip on every launch to answer a question whose answer
/// cannot change what happens.
fn may_mint(status: &IdentityStatus) -> Result<(), MachineError> {
    if status.private_keys_held {
        return Ok(());
    }
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

/// Publishes this account's signing identity, minting one first if the
/// account provably has none.
///
/// Idempotent once this device holds the private keys: call it on every
/// launch. What it will not do is mint a second identity for an account that
/// already has one -- see this module's own documentation for why that is
/// the point rather than a precaution.
///
/// # What a caller must do next
///
/// Nothing here reaches the network; this library performs no request. On
/// success, drain [`crate::take_outgoing_requests`] and send what it hands
/// back **in the order it hands it back**: the device keys first if present,
/// then `signing_keys_upload`, then `signature_upload`, because a signature
/// may reference a key that is not published yet. Report each sent with
/// [`crate::mark_request_sent`].
///
/// The `signing_keys_upload` request is the one that needs user-interactive
/// authentication. Expect the first attempt to be refused with a challenge,
/// merge an `auth` object into the body, and send it again; the request id
/// stays valid across any number of refused attempts.
///
/// # Refusals
///
/// [`MachineError::AccountKeysNotFetched`] means this process has not yet
/// asked the server about this account, so it cannot know whether minting
/// would destroy an existing identity. **This call queues that key query
/// before returning it**, so the remedy is the ordinary loop: drain the
/// pump, send, report sent, call this again.
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
                    // `identities/manager.rs:836-852`), which after the
                    // first sync it always is -- so on a second process for
                    // the same store, nothing would ever ask again and this
                    // refusal would be permanent. Asking out-of-band costs
                    // one request and removes that trap entirely.
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
    /// covers the two cases those cannot reach cheaply: that holding the
    /// private keys overrides both refusals (a launch-time republication
    /// must not be blocked by a key query nobody has answered in this
    /// process), and that no combination of the three flags produces a
    /// fourth outcome.
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
                    let expected = if private_keys_held {
                        Ok(())
                    } else if !account_keys_fetched {
                        Err(MachineError::AccountKeysNotFetched)
                    } else if identity_known {
                        Err(MachineError::IdentityAlreadyExists)
                    } else {
                        Ok(())
                    };
                    assert_eq!(may_mint(&status), expected, "for {status:?}");
                }
            }
        }

        // Named separately rather than left to be read out of the loop
        // above, because it is the one row the milestone exists for: asked
        // nothing, hold nothing, know nothing. A gate written as "is the
        // local identity empty" serves this row.
        assert_eq!(
            may_mint(&IdentityStatus {
                account_keys_fetched: false,
                identity_known: false,
                private_keys_held: false,
            }),
            Err(MachineError::AccountKeysNotFetched)
        );
    }
}
